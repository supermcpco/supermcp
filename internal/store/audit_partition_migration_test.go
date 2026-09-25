package store_test

import (
	"context"
	"io"
	"log/slog"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// beforePartitions is the last schema version without migration 00033.
const beforePartitions = 32

// TestAuditPartitionMigrationCopiesResumesAndSwaps runs migration 00033 over
// a real hash chain, the way it goes wrong in practice: refused while
// something else is connected, then stopped part-way through the copy,
// then finished after events that were already copied have been scrubbed,
// put under legal hold and pseudonymised, and after more were written.
func TestAuditPartitionMigrationCopiesResumesAndSwaps(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	target := scratchDatabase(ctx, t, dsn, "partitions")

	// The previous schema, with a chain on it.
	func() {
		st := openStore(ctx, t, target)
		defer st.Close()
		sqldb := stdlib.OpenDBFromPool(st.Maint)
		defer func() { _ = sqldb.Close() }()
		provider, err := goose.NewProvider(goose.DialectPostgres, sqldb, os.DirFS("migrations"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provider.UpTo(ctx, beforePartitions); err != nil {
			t.Fatalf("migrate to %d: %v", beforePartitions, err)
		}
	}()
	// Three months of events, so the copy lands in more than one partition,
	// and a checkpoint for verify to match across the swap.
	for _, age := range []time.Duration{70 * 24 * time.Hour, 40 * 24 * time.Hour, time.Hour} {
		appendEvents(ctx, t, target, age, 15)
	}
	withDB(ctx, t, target, func(db *tenant.DB) {
		if err := (&audit.Reader{DB: db}).Anchor(ctx, nil); err != nil {
			t.Fatalf("anchoring the chain before the upgrade: %v", err)
		}
	})
	before := seqsOf(ctx, t, target, "audit_events")
	// 00030 to 00032 may not exist yet on this branch; whatever is below 33.
	prior := versionOf(ctx, t, target)

	// 1. Something else is connected: the copy does not start.
	waitForOtherSessions(ctx, t, target)
	other, err := pgx.Connect(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	err = migrateErr(ctx, t, target)
	_ = other.Close(ctx)
	if err == nil || !strings.Contains(err.Error(), "cannot be copied while the application is connected") {
		t.Fatalf("with another session connected the migration returned %v; it must refuse to copy", err)
	}

	// 2. A copy that stops after two batches of ten, as a failure would.
	stopping := withParams(t, target, map[string]string{"supermcp.audit_copy_batch": "10", "supermcp.audit_copy_batches": "2"})
	if err := migrateAlone(ctx, t, stopping); err == nil || !strings.Contains(err.Error(), "stopped after 2 batches") {
		t.Fatalf("the interrupted copy returned %v, want it stopped after 2 batches", err)
	}
	var copiedThrough, copied int64
	queryRow(ctx, t, target, `SELECT (SELECT copied_through FROM audit_events_copy_progress), (SELECT count(*) FROM audit_events_new)`,
		&copiedThrough, &copied)
	if copied != 20 || copiedThrough != before[19] {
		t.Fatalf("after two batches of ten, %d rows are copied through seq %d; want 20 through %d", copied, copiedThrough, before[19])
	}
	if v := versionOf(ctx, t, target); v != prior {
		t.Fatalf("an interrupted copy left the schema at version %d, want %d; goose must not record 33", v, prior)
	}

	// 3. While it is stopped, a replica that should not be running changes
	// rows that are already copied, and appends.
	scrubbed, held, renamed, removed := before[2], before[4], before[6], before[0]
	execSQL(ctx, t, target, `UPDATE audit_events SET diff = NULL, payload = NULL, scrubbed_at = now() WHERE seq = $1`, scrubbed)
	execSQL(ctx, t, target, `UPDATE audit_events SET legal_hold = true WHERE seq = $1`, held)
	execSQL(ctx, t, target, `UPDATE audit_events SET actor_display = 'pseudonym' WHERE seq = $1`, renamed)
	appendEvents(ctx, t, target, 0, 3)
	// And retention, on the old release, cuts the oldest event.
	execSQL(ctx, t, target, `INSERT INTO audit_anchors (seq, hash, kind)
		SELECT seq, hash, 'retention_cut' FROM audit_events WHERE seq = $1`, removed)
	execSQL(ctx, t, target, `DELETE FROM audit_events WHERE seq = $1`, removed)

	// 4. The rerun continues and swaps.
	if err := migrateAlone(ctx, t, target); err != nil {
		t.Fatalf("the rerun after the interrupted copy failed: %v", err)
	}
	var kind string
	queryRow(ctx, t, target, `SELECT relkind::text FROM pg_class WHERE oid = 'audit_events'::regclass`, &kind)
	if kind != "p" {
		t.Fatalf("audit_events has relkind %q after the migration, want a partitioned table", kind)
	}
	oldSeqs := seqsOf(ctx, t, target, "audit_events_old")
	newSeqs := seqsOf(ctx, t, target, "audit_events")
	if !slices.Equal(newSeqs, oldSeqs) || len(newSeqs) != len(before)+2 {
		t.Fatalf("the copy holds %d events and the old table %d (%d before, 3 appended, 1 cut); every seq once, none missing:\nnew %v\nold %v",
			len(newSeqs), len(oldSeqs), len(before), newSeqs, oldSeqs)
	}
	var isScrubbed, isHeld bool
	var display string
	queryRowArgs(ctx, t, target, `SELECT
			(SELECT scrubbed_at IS NOT NULL AND diff IS NULL AND payload IS NULL FROM audit_events WHERE seq = $1),
			(SELECT legal_hold FROM audit_events WHERE seq = $2),
			(SELECT actor_display FROM audit_events WHERE seq = $3)`,
		[]any{scrubbed, held, renamed}, &isScrubbed, &isHeld, &display)
	if !isScrubbed || !isHeld || display != "pseudonym" {
		t.Errorf("changes made to copied events during the copy were lost: scrubbed %v, held %v, display %q", isScrubbed, isHeld, display)
	}
	if slices.Contains(newSeqs, removed) {
		t.Errorf("seq %d was cut from the old table during the copy and is still in the copy", removed)
	}

	// The next event takes the number the old table would have given it.
	var oldLast, next int64
	queryRow(ctx, t, target, `SELECT last_value FROM audit_events_old_seq_seq`, &oldLast)
	queryRow(ctx, t, target, `SELECT nextval(pg_get_serial_sequence('audit_events', 'seq'))`, &next)
	if next != oldLast+1 {
		t.Errorf("the sequence continues at %d after the swap, want %d", next, oldLast+1)
	}

	// The chain verifies across the swap, and keeps growing after it.
	appendEvents(ctx, t, target, 0, 2)
	verifyChain(ctx, t, target, len(before)+4)

	// 5. A rerun after the swap changes nothing.
	execSQL(ctx, t, target, `DELETE FROM goose_db_version WHERE version_id >= 33`)
	if err := migrateAlone(ctx, t, target); err != nil {
		t.Fatalf("rerunning 33 after the swap failed: %v", err)
	}
	if again := seqsOf(ctx, t, target, "audit_events"); len(again) != len(before)+4 {
		t.Errorf("rerunning 33 after the swap left %d events, want %d", len(again), len(before)+4)
	}
	if !tableExists(ctx, t, target, "audit_events_old") {
		t.Error("rerunning 33 after the swap removed audit_events_old")
	}

	// 6. Down, and up again while audit_events_old is still there: refused,
	// until the operator has dropped it.
	func() {
		st := openStore(ctx, t, target)
		defer st.Close()
		sqldb := stdlib.OpenDBFromPool(st.Maint)
		defer func() { _ = sqldb.Close() }()
		provider, err := goose.NewProvider(goose.DialectPostgres, sqldb, os.DirFS("migrations"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provider.DownTo(ctx, beforePartitions); err != nil {
			t.Fatalf("migrate down to %d: %v", beforePartitions, err)
		}
	}()
	queryRow(ctx, t, target, `SELECT relkind::text FROM pg_class WHERE oid = 'audit_events'::regclass`, &kind)
	if kind != "r" {
		t.Fatalf("after migrating down audit_events has relkind %q, want a plain table", kind)
	}
	verifyChain(ctx, t, target, len(before)+4)
	if err := migrateAlone(ctx, t, target); err == nil || !strings.Contains(err.Error(), "audit_events_old is still here") {
		t.Fatalf("upgrading again with audit_events_old present returned %v; it must refuse", err)
	}
	execSQL(ctx, t, target, `DROP TABLE audit_events_old`)
	execSQL(ctx, t, target, `DROP TABLE IF EXISTS audit_events_new CASCADE`)
	execSQL(ctx, t, target, `DROP TABLE IF EXISTS audit_events_copy_progress`)
	if err := migrateAlone(ctx, t, target); err != nil {
		t.Fatalf("upgrading again after dropping audit_events_old failed: %v", err)
	}
	verifyChain(ctx, t, target, len(before)+4)
}

func openStore(ctx context.Context, t *testing.T, dsn string) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, dsn, dsn, slog.New(slog.NewTextHandler(io.Discard, nil)), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// withDB runs fn with a store that is closed again before withDB returns,
// so no session of it is left for the migration's guard to see.
func withDB(ctx context.Context, t *testing.T, dsn string, fn func(*tenant.DB)) {
	t.Helper()
	st := openStore(ctx, t, dsn)
	defer st.Close()
	fn(&tenant.DB{App: st.App, Maint: st.Maint, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
}

// migrateErr runs `supermcp migrate` against dsn and returns what it
// returned.
func migrateErr(ctx context.Context, t *testing.T, dsn string) error {
	t.Helper()
	st := openStore(ctx, t, dsn)
	defer st.Close()
	return st.Migrate(ctx, true)
}

// migrateAlone is migrateErr once the sessions of stores this test closed
// have left: a backend outlives its client by a moment, and the
// migration's guard would see it.
func migrateAlone(ctx context.Context, t *testing.T, dsn string) error {
	t.Helper()
	waitForOtherSessions(ctx, t, dsn)
	st := openStore(ctx, t, dsn)
	defer st.Close()
	return st.Migrate(ctx, true)
}

// appendEvents writes n events through the audit writer with a clock age in
// the past.
func appendEvents(ctx context.Context, t *testing.T, dsn string, age time.Duration, n int) {
	t.Helper()
	withDB(ctx, t, dsn, func(db *tenant.DB) {
		w := audit.NewWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)), //nolint:contextcheck // the writer appends from its own goroutine
			audit.Options{Now: func() time.Time { return time.Now().Add(-age) }})
		defer w.Close()
		for i := range n {
			if err := w.EmitSync(ctx, audit.Event{OrgID: "org_parts", Category: audit.CategoryAdmin, Action: "connector.update",
				Outcome: audit.Success, ActorKind: "user", ActorID: "u_parts", ActorDisplay: "a@example.com",
				Diff: map[string]any{"after": i}, Payload: map[string]any{"n": i}, Meta: map[string]any{"i": i}}); err != nil {
				t.Fatalf("appending an event: %v", err)
			}
		}
	})
}

func verifyChain(ctx context.Context, t *testing.T, dsn string, want int) {
	t.Helper()
	withDB(ctx, t, dsn, func(db *tenant.DB) {
		res, err := (&audit.Reader{DB: db}).Verify(ctx, 0, 0)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !res.Valid || res.Checked != int64(want) || res.Anchors < 1 {
			t.Errorf("verify over the whole chain: %+v; want it valid over %d events with the checkpoint matched", res, want)
		}
	})
}

func seqsOf(ctx context.Context, t *testing.T, dsn, table string) []int64 {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	rows, err := conn.Query(ctx, `SELECT seq FROM `+pgx.Identifier{table}.Sanitize()+` ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	seqs, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		t.Fatal(err)
	}
	return seqs
}

// queryRow reads one row with no arguments into dest.
func queryRow(ctx context.Context, t *testing.T, dsn, sql string, dest ...any) {
	t.Helper()
	queryRowArgs(ctx, t, dsn, sql, nil, dest...)
}

func queryRowArgs(ctx context.Context, t *testing.T, dsn, sql string, args []any, dest ...any) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if err := conn.QueryRow(ctx, sql, args...).Scan(dest...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func execSQL(ctx context.Context, t *testing.T, dsn, sql string, args ...any) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func tableExists(ctx context.Context, t *testing.T, dsn, name string) bool {
	t.Helper()
	var exists bool
	queryRowArgs(ctx, t, dsn, `SELECT to_regclass('public.' || quote_ident($1)) IS NOT NULL`, []any{name}, &exists)
	return exists
}

// withParams adds run-time parameters to a connection URL.
func withParams(t *testing.T, dsn string, params map[string]string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// waitForOtherSessions returns once no client session but the one asking
// is connected to dsn's database.
func waitForOtherSessions(ctx context.Context, t *testing.T, dsn string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(10 * time.Second)
	for {
		var n int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND pid <> pg_backend_pid() AND backend_type = 'client backend'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatalf("%d sessions of stores this test closed are still connected after ten seconds", n)
		}
	}
}

// versionOf is the newest applied migration, read without keeping a store
// open.
func versionOf(ctx context.Context, t *testing.T, dsn string) int64 {
	t.Helper()
	var v int64
	queryRow(ctx, t, dsn, `SELECT COALESCE(max(version_id), 0) FROM goose_db_version WHERE is_applied`, &v)
	return v
}
