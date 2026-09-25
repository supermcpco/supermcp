package governance_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/governance"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// These tests want the real database: what is being checked is how
// Postgres stores a snapshot and how it hands one back, which no fake can
// tell us. Requires DATABASE_URL; skipped otherwise, like the store tests.

type fixture struct {
	svc   *governance.Service
	db    *tenant.DB
	orgID string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := t.Context()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	maint, err := store.Open(ctx, url, url, log, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := maint.Migrate(ctx, true); err != nil {
		t.Fatal(err)
	}
	maint.Close()

	st, err := store.Open(ctx, url, url, log, store.Options{AppRole: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}

	// Each test gets its own organisation, so they can run together and so
	// that dropping it at the end takes the revisions with it.
	orgID := "rev_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	if err := db.Bypass(ctx, "test seed", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, slug, name) VALUES ($1,$1,$1)`, orgID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Bypass(context.Background(), "test cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
			return err
		})
	})
	return &fixture{svc: governance.New(db, uuid.NewString), db: db, orgID: orgID}
}

// record writes one revision the way a service would: inside the
// transaction that made the change.
func (f *fixture) record(ctx context.Context, r governance.Revision) error {
	return f.db.Tx(tenant.WithOrg(ctx, f.orgID), func(tx pgx.Tx) error {
		return f.svc.RecordRevision(ctx, tx, r)
	})
}

func (f *fixture) mustRecord(t *testing.T, r governance.Revision) {
	t.Helper()
	if err := f.record(t.Context(), r); err != nil {
		t.Fatalf("record %s %s: %v", r.Action, r.EntityID, err)
	}
}

func TestRevisionNumbersRisePerEntity(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := t.Context()

	for i, action := range []string{governance.ActionCreate, governance.ActionUpdate, governance.ActionUpdate} {
		f.mustRecord(t, governance.Revision{Kind: governance.KindConnector, EntityID: "c1", Action: action,
			Entity: map[string]any{"name": "one", "step": i}})
	}
	// A second entity keeps its own count: the numbering is the history of
	// one thing, not of the organisation.
	f.mustRecord(t, governance.Revision{Kind: governance.KindConnector, EntityID: "c2",
		Action: governance.ActionCreate, Entity: map[string]any{"name": "two"}})

	list, err := f.svc.List(ctx, f.orgID, governance.KindConnector, "c1", 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if got := numbers(list); !slices.Equal(got, []int{3, 2, 1}) {
		t.Errorf("newest first: got %v, want [3 2 1]", got)
	}
	if list[0].Action != governance.ActionUpdate || list[2].Action != governance.ActionCreate {
		t.Errorf("actions came back as %q…%q", list[0].Action, list[2].Action)
	}

	second, err := f.svc.List(ctx, f.orgID, governance.KindConnector, "c2", 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if got := numbers(second); !slices.Equal(got, []int{1}) {
		t.Errorf("second entity started at %v, want [1]", got)
	}

	// Paging walks backwards through the history without repeating itself.
	page, err := f.svc.List(ctx, f.orgID, governance.KindConnector, "c1", 3, 50)
	if err != nil {
		t.Fatal(err)
	}
	if got := numbers(page); !slices.Equal(got, []int{2, 1}) {
		t.Errorf("page below 3: got %v, want [2 1]", got)
	}
}

// Two writers on one entity must not both decide they are the second
// revision. They are serialised in the database, so the test asserts on
// the whole set of numbers rather than on who won.
func TestConcurrentWritersDoNotCollide(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := t.Context()

	const writers, each = 2, 5
	var wg sync.WaitGroup
	errs := make(chan error, writers*each)
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				if err := f.record(ctx, governance.Revision{Kind: governance.KindServer, EntityID: "s1",
					Action: governance.ActionUpdate, Entity: map[string]any{"writer": w, "step": i}}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent write: %v", err)
	}

	list, err := f.svc.List(ctx, f.orgID, governance.KindServer, "s1", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, r := range list {
		if seen[r.Number] {
			t.Errorf("revision %d was handed out twice", r.Number)
		}
		seen[r.Number] = true
	}
	for n := 1; n <= writers*each; n++ {
		if !seen[n] {
			t.Errorf("revision %d is missing from the history", n)
		}
	}
	if len(list) != writers*each {
		t.Errorf("history has %d revisions, want %d", len(list), writers*each)
	}
}

// The point of storing `json` rather than `jsonb`: jsonb would hand back
// the keys shortest-first, and a snapshot that comes back reordered is not
// the snapshot that was taken.
func TestSnapshotComesBackAsItWasStored(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	f.mustRecord(t, governance.Revision{Kind: governance.KindConnector, EntityID: "c1",
		Action: governance.ActionCreate, Entity: map[string]any{"aaa": "first", "zz": "last"}})

	r, err := f.svc.Get(t.Context(), f.orgID, governance.KindConnector, "c1", 1)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"aaa":"first","zz":"last"}`
	if string(r.Snapshot) != want {
		t.Errorf("snapshot came back as %s, want %s", r.Snapshot, want)
	}
}

func TestSnapshotKeepsNoCredentialValue(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	const value = "pk_live_the_actual_secret"
	f.mustRecord(t, governance.Revision{Kind: governance.KindConnector, EntityID: "c1",
		Action: governance.ActionCreate,
		Entity: map[string]any{"name": "billing", "apiKey": value, "token": value},
		Diff:   audit.Changes(map[string]any{"apiKey": "old"}, map[string]any{"apiKey": value})})

	r, err := f.svc.Get(t.Context(), f.orgID, governance.KindConnector, "c1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(r.Snapshot), value) {
		t.Fatalf("the credential value is in the snapshot: %s", r.Snapshot)
	}
	// A digest still has to stand in its place, or nobody can tell a
	// rotation from an untouched field.
	fields, err := r.Fields()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"apiKey", "token"} {
		if got, _ := fields[key].(string); !strings.HasPrefix(got, "<redacted:") {
			t.Errorf("%s came back as %q, want a digest", key, got)
		}
	}
	if r.Diff == nil || strings.Contains(fmt.Sprint(r.Diff.After), value) {
		t.Errorf("the diff kept the credential value: %+v", r.Diff)
	}
}

// A rollback puts an earlier snapshot back through the service that owns
// the entity, which records the result like any other change. What must
// survive is the revision that was wrong: the numbering only goes
// forwards.
func TestRestoreWritesANewRevisionWithTheOldSnapshot(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := t.Context()

	original := map[string]any{"name": "one", "baseUrl": "https://one.example", "enabled": true}
	f.mustRecord(t, governance.Revision{Kind: governance.KindServer, EntityID: "s1",
		Action: governance.ActionCreate, Entity: original})
	f.mustRecord(t, governance.Revision{Kind: governance.KindServer, EntityID: "s1",
		Action: governance.ActionUpdate, Entity: map[string]any{"name": "two", "baseUrl": "https://two.example", "enabled": false}})

	restore, err := f.svc.Snapshot(ctx, f.orgID, governance.KindServer, "s1", 1)
	if err != nil {
		t.Fatal(err)
	}
	f.mustRecord(t, governance.Revision{Kind: governance.KindServer, EntityID: "s1",
		Action: governance.ActionUpdate, Entity: restore})

	first, err := f.svc.Get(ctx, f.orgID, governance.KindServer, "s1", 1)
	if err != nil {
		t.Fatal(err)
	}
	third, err := f.svc.Get(ctx, f.orgID, governance.KindServer, "s1", 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(third.Snapshot) != string(first.Snapshot) {
		t.Errorf("restored snapshot is %s, want %s", third.Snapshot, first.Snapshot)
	}
	// The revision that was rolled back is still there, and still says
	// what it said.
	second, err := f.svc.Get(ctx, f.orgID, governance.KindServer, "s1", 2)
	if err != nil {
		t.Fatal(err)
	}
	var was map[string]any
	if err := json.Unmarshal(second.Snapshot, &was); err != nil {
		t.Fatal(err)
	}
	if was["name"] != "two" {
		t.Errorf("the corrected revision was rewritten: %s", second.Snapshot)
	}
}

func TestReadsAreScopedToTheirOrganisation(t *testing.T) {
	t.Parallel()
	a, b := newFixture(t), newFixture(t)

	a.mustRecord(t, governance.Revision{Kind: governance.KindConnector, EntityID: "shared",
		Action: governance.ActionCreate, Entity: map[string]any{"name": "a"}})

	if _, err := b.svc.Get(t.Context(), b.orgID, governance.KindConnector, "shared", 1); !errors.Is(err, governance.ErrNotFound) {
		t.Errorf("another organisation read the revision: %v", err)
	}
	list, err := b.svc.List(t.Context(), b.orgID, governance.KindConnector, "shared", 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("another organisation listed %d revisions", len(list))
	}
}

func TestRecordRejectsWhatItCannotStore(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	tests := []struct {
		name string
		rev  governance.Revision
	}{
		{"no entity id", governance.Revision{Kind: governance.KindConnector, Action: governance.ActionCreate, Entity: map[string]any{}}},
		{"unknown kind", governance.Revision{Kind: "policy", EntityID: "x", Action: governance.ActionCreate, Entity: map[string]any{}}},
		{"unknown action", governance.Revision{Kind: governance.KindTool, EntityID: "x", Action: "restore", Entity: map[string]any{}}},
		{"no snapshot", governance.Revision{Kind: governance.KindTool, EntityID: "x", Action: governance.ActionDelete}},
		{"snapshot is not an object", governance.Revision{Kind: governance.KindTool, EntityID: "x", Action: governance.ActionDelete, Entity: []string{"nope"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := f.record(t.Context(), tt.rev); err == nil {
				t.Error("the revision was accepted")
			}
		})
	}
}

func TestGetUnknownRevision(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	if _, err := f.svc.Snapshot(t.Context(), f.orgID, governance.KindConnector, "c1", 7); !errors.Is(err, governance.ErrNotFound) {
		t.Errorf("Snapshot of a revision that never happened: %v", err)
	}
}

func numbers(list []governance.Revision) []int {
	out := make([]int, 0, len(list))
	for _, r := range list {
		out = append(out, r.Number)
	}
	return out
}

// The history shows who made each change: the name recorded with it, the
// member's name or address when the caller gave none, and, for a row
// recorded before names were kept, the member looked up when it is read.
func TestActorIsShownByName(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := t.Context()
	named, bare, outsider := f.orgID+"_named", f.orgID+"_bare", f.orgID+"_out"
	seed := func(q string, args ...any) {
		t.Helper()
		if err := f.db.Bypass(ctx, "test seed", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, q, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	seed(`INSERT INTO users (id, email, name) VALUES ($1, $1 || '@rev.test', 'Ada Lovelace'), ($2, $2 || '@rev.test', ''), ($3, $3 || '@rev.test', 'Not A Member')`,
		named, bare, outsider)
	seed(`INSERT INTO organization_members (user_id, organization_id) VALUES ($1, $3), ($2, $3)`, named, bare, f.orgID)
	t.Cleanup(func() {
		_ = f.db.Bypass(context.Background(), "test cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `DELETE FROM users WHERE id = ANY($1)`, []string{named, bare, outsider})
			return err
		})
	})

	for _, r := range []governance.Revision{
		{ActorID: named},
		{ActorID: bare},
		{ActorID: outsider},
		{ActorID: named, ActorDisplay: "Given by the caller"},
		{},
		{ActorID: named},
	} {
		r.Kind, r.EntityID, r.Action, r.Entity = governance.KindConnector, "c1", governance.ActionUpdate, map[string]any{"name": "x"}
		f.mustRecord(t, r)
	}
	// Revision 1 as a row written before the name was kept, by somebody
	// who has since changed it.
	seed(`UPDATE revisions SET actor_display = '' WHERE organization_id = $1 AND entity_id = 'c1' AND revision = 1`, f.orgID)
	seed(`UPDATE users SET name = 'Ada King' WHERE id = $1`, named)

	list, err := f.svc.List(ctx, f.orgID, governance.KindConnector, "c1", 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]string{}
	for _, r := range list {
		got[r.Number] = r.ActorDisplay
	}
	want := map[int]string{
		1: "Ada King",         // looked up when read
		2: bare + "@rev.test", // no name, so the address
		3: "",                 // not a member: not shown
		4: "Given by the caller",
		5: "",             // no actor at all
		6: "Ada Lovelace", // kept as it was when recorded
	}
	for n, w := range want {
		if got[n] != w {
			t.Errorf("revision %d shown as %q, want %q", n, got[n], w)
		}
	}
	if r, err := f.svc.Get(ctx, f.orgID, governance.KindConnector, "c1", 1); err != nil || r.ActorDisplay != "Ada King" {
		t.Errorf("get revision 1: %q, %v", r.ActorDisplay, err)
	}
}
