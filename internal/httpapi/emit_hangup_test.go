package httpapi

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// auditChainLock is the advisory lock the audit writer takes for each
// append (audit.chainLockID). Holding it stalls the writer, which is how
// this test fills the queue.
const auditChainLock int64 = 0xA0D17

// TestAuditEventSurvivesTheCallerHangingUp: under
// SUPERMCP_AUDIT_ON_UNAVAILABLE=block, with the audit queue full, a
// mutation's event is emitted on a request whose caller has already hung
// up. It must wait for room and be recorded, not dropped because the
// request's context ended. Requires DATABASE_URL.
func TestAuditEventSurvivesTheCallerHangingUp(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx, cancelAll := context.WithTimeout(context.Background(), time.Minute)
	defer cancelAll()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	maint, err := store.Open(ctx, dsn, dsn, log, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := maint.Migrate(ctx, true); err != nil {
		maint.Close()
		t.Fatal(err)
	}
	t.Cleanup(maint.Close)

	// The writer's own pool, named, so the test can tell when it is the
	// one waiting on the chain lock.
	const appName = "supermcp_emit_hangup_test"
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = appName
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	db := &tenant.DB{App: pool, Maint: pool, Log: log}

	const org = "emit_hangup"
	purge := func() {
		if _, err := maint.Maint.Exec(context.WithoutCancel(ctx), `DELETE FROM audit_events WHERE organization_id = $1`, org); err != nil {
			t.Fatal(err)
		}
	}
	purge()
	t.Cleanup(purge)

	w := audit.NewWriter(db, log, audit.Options{Buffer: 1, OnUnavailable: audit.UnavailableBlock}) //nolint:contextcheck // the writer appends from its own goroutine
	t.Cleanup(w.Close)

	// Stall the writer on an event of its own, then fill the queue.
	lock, err := maint.Maint.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := lock.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditChainLock); err != nil {
		t.Fatal(err)
	}
	filler := func(action string) audit.Event {
		return audit.Event{Category: audit.CategoryAdmin, Action: action, Outcome: audit.Success, OrgID: org,
			ActorKind: "system", ActorID: "test"}
	}
	w.Emit(ctx, filler("test.stalled"))
	flushed := make(chan error, 1)
	go func() { flushed <- w.Flush(ctx) }()
	waitFor(ctx, t, "the writer to wait on the chain lock", func() bool {
		var n int
		err := maint.Maint.QueryRow(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid)
			WHERE l.locktype = 'advisory' AND NOT l.granted AND a.application_name = $1`, appName).Scan(&n)
		return err == nil && n > 0
	})
	w.Emit(ctx, filler("test.queued"))
	if got := w.QueueDepth(); got != 1 {
		t.Fatalf("queue depth %d, want the queue full at 1", got)
	}

	// The mutation has committed; the caller hangs up; then its event is
	// emitted.
	const id = "req-emit-hangup-1"
	gone, hangUp := context.WithCancel(context.WithValue(ctx, middleware.RequestIDKey, id))
	gone = authz.WithPrincipal(gone, &authz.Principal{Kind: authz.KindUser, ID: "u_hangup", OrgID: org, AuthMethod: "session"})
	hangUp()
	started, emitted := make(chan struct{}), make(chan struct{})
	go func() {
		close(started)
		Deps{Audit: w}.admin(gone, "role.create", "role", "r_hangup", "Hung up", nil)
		close(emitted)
	}()
	<-started
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-emitted:
	case <-ctx.Done():
		t.Fatal("the event never found room in the queue")
	}
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	if n := w.DroppedTotal(); n != 0 {
		t.Errorf("%d events dropped, want none", n)
	}
	var n int
	if err := maint.Maint.QueryRow(ctx, `SELECT count(*) FROM audit_events
		WHERE organization_id = $1 AND action = 'role.create' AND request_id = $2`, org, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d role.create events recorded for the hung-up request, want 1", n)
	}
}

// waitFor polls cond until it holds or ctx ends.
func waitFor(ctx context.Context, t *testing.T, what string, cond func() bool) {
	t.Helper()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for !cond() {
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}
