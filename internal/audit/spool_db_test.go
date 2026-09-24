// These tests take the database away in the middle of writing and bring it
// back, which is the only way to see what the spool is for. They share the
// live-Postgres harness in chain_test.go.
package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// deadPool is a pool pointed at a port nothing is listening on: acquiring a
// connection fails the way an unreachable database does.
func deadPool(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://nobody:nothing@127.0.0.1:1/none?sslmode=disable")
	if err != nil {
		t.Fatalf("parse the unreachable pool's configuration: %v", err)
	}
	cfg.ConnConfig.ConnectTimeout = 2 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("build the unreachable pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// The whole point of the spool: events written while the database was away
// reach the chain when it comes back, in the order they were written, and
// the chain still verifies.
func TestSpooledEventsReachTheChainInOrder(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db)
	dir := t.TempDir()

	// The database is away. Everything this writer is given goes to disk.
	away := &tenant.DB{App: db.App, Maint: deadPool(ctx, t), Log: testLog()}
	stranded := audit.NewWriter(away, testLog(), audit.Options{
		OnUnavailable: audit.UnavailableSpool, SpoolDir: dir})
	for i := range 3 {
		stranded.Emit(ctx, bare(s.org(), "connector.update", i))
	}
	if err := stranded.Flush(ctx); err == nil {
		t.Fatal("a flush against a database that is not there reported success")
	}
	if stranded.SpoolDepth() != 3 {
		t.Fatalf("spool depth = %d, want the three events the database would not take", stranded.SpoolDepth())
	}
	if stranded.Dropped() != 0 {
		t.Fatalf("%d events were dropped; a spooled event is not a dropped one", stranded.Dropped())
	}
	stranded.Close()

	// And back. A new writer over the same directory stands in for the
	// restart that a real outage usually involves.
	recovered := audit.NewWriter(db, testLog(), audit.Options{
		OnUnavailable: audit.UnavailableSpool, SpoolDir: dir})
	defer recovered.Close()
	for i := range 2 {
		recovered.Emit(ctx, bare(s.org(), "connector.delete", i))
	}
	if err := recovered.Flush(ctx); err != nil {
		t.Fatalf("flushing after the database came back failed: %v", err)
	}
	if recovered.SpoolDepth() != 0 {
		t.Fatalf("spool depth = %d after recovery, want everything replayed", recovered.SpoolDepth())
	}

	r := &audit.Reader{DB: db}
	got, err := r.List(tenant.WithOrg(ctx, s.org()), audit.Query{OrgID: s.org(), Limit: 50})
	if err != nil {
		t.Fatalf("reading the stream back: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("the stream holds %d events, want the three that waited on disk and the two that did not", len(got))
	}
	// List is newest first; the chain is oldest first.
	for i, j := 0, len(got)-1; i < j; i, j = i+1, j-1 {
		got[i], got[j] = got[j], got[i]
	}
	for i, rec := range got {
		wantAction := "connector.update"
		wantSpooled := true
		if i >= 3 {
			wantAction, wantSpooled = "connector.delete", false
		}
		if rec.Action != wantAction {
			t.Fatalf("event %d is %q, want %q: a spooled event must keep its place ahead of one written after it",
				i, rec.Action, wantAction)
		}
		spooled, _ := rec.Meta["spooled"].(bool)
		if spooled != wantSpooled {
			t.Fatalf("event %d says spooled=%v, want %v", i, spooled, wantSpooled)
		}
		if wantSpooled {
			if _, ok := rec.Meta["occurredAt"].(string); !ok {
				t.Fatalf("event %d does not record when it happened: %v", i, rec.Meta)
			}
			// The row's own time is when it reached the chain, because a
			// row that can be backdated can drag the stream into a
			// retention cut that then looks lawful.
			if rec.Time.Before(time.Now().Add(-time.Hour)) {
				t.Fatalf("event %d is stamped %s; a replayed row must not be backdated", i, rec.Time)
			}
		}
	}

	lo, hi := s.bounds(ctx)
	res, err := r.Verify(ctx, lo, hi)
	if err != nil {
		t.Fatalf("Verify over seq %d..%d failed: %v", lo, hi, err)
	}
	if !res.Valid {
		t.Fatalf("the chain is broken at seq %d (%q) after events were replayed from the spool", res.BrokenAt, res.Explained)
	}
	if res.Checked != 5 {
		t.Fatalf("Verify walked %d rows, want the 5 that were written", res.Checked)
	}
}

// A writer that is not asked to spool keeps the behaviour it had: the
// events are lost and counted, not held.
func TestWithoutSpoolingEventsAreStillCounted(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	away := &tenant.DB{App: db.App, Maint: deadPool(ctx, t), Log: testLog()}
	w := audit.NewWriter(away, testLog(), audit.Options{OnUnavailable: audit.UnavailableDegrade})
	defer w.Close()

	w.Emit(ctx, bare("audit_t_no_spool", "connector.update", 1))
	if err := w.Flush(ctx); err == nil {
		t.Fatal("a flush against a database that is not there reported success")
	}
	if w.SpoolDepth() != 0 {
		t.Fatalf("spool depth = %d, want nothing spooled when spooling was not asked for", w.SpoolDepth())
	}
}
