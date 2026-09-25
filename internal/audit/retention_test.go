package audit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/tenant"
)

func TestRetentionSettingRoundTripAndBounds(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db)
	seedOrgs(ctx, t, db, s.orgs...)
	org := s.org()
	r := audit.NewRetention(db, testLog())

	got, err := r.Setting(ctx, org)
	if err != nil {
		t.Fatalf("reading an organisation's retention failed: %v", err)
	}
	if got.Days != audit.DefaultRetentionDays || got.Configured {
		t.Errorf("an organisation that never chose reports %+v; it should be on the %d-day default", got, audit.DefaultRetentionDays)
	}

	tests := []struct {
		name    string
		days    int
		refused bool
	}{
		{name: "below the floor", days: audit.MinRetentionDays - 1, refused: true},
		{name: "zero", days: 0, refused: true},
		{name: "above the ceiling", days: audit.MaxRetentionDays + 1, refused: true},
		{name: "the floor", days: audit.MinRetentionDays},
		{name: "the ceiling", days: audit.MaxRetentionDays},
		{name: "in between", days: 180},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before, err := r.Setting(ctx, org)
			if err != nil {
				t.Fatal(err)
			}
			err = r.SetDays(ctx, org, tt.days)
			var outOfRange *audit.RetentionRangeError
			if tt.refused {
				if !errors.As(err, &outOfRange) {
					t.Fatalf("SetDays(%d) returned %v; it should refuse with a RetentionRangeError", tt.days, err)
				}
				if after, _ := r.Setting(ctx, org); after != before {
					t.Errorf("a refused SetDays(%d) changed the setting from %+v to %+v", tt.days, before, after)
				}
				return
			}
			if err != nil {
				t.Fatalf("SetDays(%d) failed: %v", tt.days, err)
			}
			after, err := r.Setting(ctx, org)
			if err != nil {
				t.Fatal(err)
			}
			if after.Days != tt.days || !after.Configured {
				t.Errorf("after SetDays(%d) the setting reads %+v", tt.days, after)
			}
		})
	}
}

// TestRetentionRunHonoursTheStoredWindow checks the sweep applies what
// SetDays stored: an organisation's content goes once it is older than its
// own window, and not before.
func TestRetentionRunHonoursTheStoredWindow(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	// Org B stays on the default, which keeps the instance-wide cut at a
	// year or more, so every row this test writes stays in the table and
	// what is under test is the scrub alone.
	s := newStream(ctx, t, db, "_a", "_b")
	seedOrgs(ctx, t, db, s.orgs...)
	orgA := s.orgs[0]
	r := audit.NewRetention(db, testLog())

	if err := r.SetDays(ctx, orgA, 100); err != nil {
		t.Fatalf("storing a 100-day window failed: %v", err)
	}
	// The timestamp is hashed, so an old event is written by a writer whose
	// clock is in the past.
	aged := []struct{ target, days int }{{target: 1, days: 120}, {target: 2, days: 95}}
	for _, a := range aged {
		age := time.Duration(a.days) * 24 * time.Hour
		w := audit.NewWriter(db, testLog(), audit.Options{Now: func() time.Time { return time.Now().Add(-age) }}) //nolint:contextcheck // the writer appends from its own goroutine
		emitSync(ctx, t, w, event(orgA, "connector.update", a.target))
		w.Close()
	}

	if err := r.Run(ctx); err != nil {
		t.Fatalf("the retention sweep failed: %v", err)
	}
	if got := scrubbedTargets(ctx, t, db, orgA); len(got) != 1 || got[0] != "c_01" {
		t.Fatalf("with a 100-day window the sweep scrubbed %v; only the 120-day-old event (c_01) is outside it", got)
	}

	// Shortening the window reaches the 95-day-old event on the next run.
	if err := r.SetDays(ctx, orgA, 90); err != nil {
		t.Fatalf("storing a 90-day window failed: %v", err)
	}
	if err := r.Run(ctx); err != nil {
		t.Fatalf("the retention sweep failed: %v", err)
	}
	if got := scrubbedTargets(ctx, t, db, orgA); len(got) != 2 {
		t.Fatalf("with a 90-day window the sweep has scrubbed %v; both events are outside it", got)
	}
	if n := len(s.seqs(ctx)); n != 2 {
		t.Errorf("%d of the 2 events are left; a window shorter than the instance-wide cut scrubs, it does not delete", n)
	}

	cut, err := r.InstanceCutDays(ctx)
	if err != nil {
		t.Fatalf("reading the instance-wide cut failed: %v", err)
	}
	if cut < audit.DefaultRetentionDays {
		t.Errorf("the instance-wide cut is %d days, but org B is on the %d-day default and the cut is the longest window", cut, audit.DefaultRetentionDays)
	}
}

// seedOrgs creates organisations for the given ids, because org_settings
// and the sweep both start from the organizations table.
func seedOrgs(ctx context.Context, t *testing.T, db *tenant.DB, ids ...string) {
	t.Helper()
	drop := func(ctx context.Context) {
		if err := db.Bypass(ctx, "audit retention test cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = ANY($1)`, ids)
			return err
		}); err != nil {
			t.Fatalf("could not remove the test organisations %v; a rerun will not be clean: %v", ids, err)
		}
	}
	drop(ctx)
	if err := db.Bypass(ctx, "audit retention test seed", func(tx pgx.Tx) error {
		for _, id := range ids {
			if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, slug, name) VALUES ($1,$1,'audit retention test')`, id); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("could not create the test organisations %v: %v", ids, err)
	}
	t.Cleanup(func() { drop(context.WithoutCancel(ctx)) })
}

// scrubbedTargets lists the target ids of an organisation's scrubbed
// events, oldest first.
func scrubbedTargets(ctx context.Context, t *testing.T, db *tenant.DB, orgID string) []string {
	t.Helper()
	var out []string
	err := db.Bypass(ctx, "audit retention test scrubbed", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT target_id FROM audit_events
			WHERE organization_id = $1 AND scrubbed_at IS NOT NULL ORDER BY seq`, orgID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("could not read which events were scrubbed: %v", err)
	}
	return out
}
