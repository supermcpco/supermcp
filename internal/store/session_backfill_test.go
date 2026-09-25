package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// TestSessionAuthenticatedAtBackfill upgrades a database holding sessions
// across migration 00024. Live sessions, more than one batch of them,
// take created_at as their authentication time; revoked and expired ones
// are left at '-infinity'; and a session opened afterwards gets now().
func TestSessionAuthenticatedAtBackfill(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db := scratchDatabase(ctx, t, dsn, "backfill")

	st := open(ctx, t, db)
	sqlDB := stdlib.OpenDBFromPool(st.Maint)
	t.Cleanup(func() { _ = sqlDB.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 23); err != nil {
		t.Fatalf("migrate to 00023: %v", err)
	}
	const live = 2500
	if _, err := st.Maint.Exec(ctx, `
INSERT INTO users (id, email, name) VALUES ('u1', 'backfill@example.test', 'Backfill');
INSERT INTO sessions (id, user_id, created_at, idle_expires_at, absolute_expires_at, auth_method)
    SELECT 'live-' || lpad(g::text, 5, '0'), 'u1', now() - interval '3 days',
           now() + interval '1 hour', now() + interval '20 days', 'password'
    FROM generate_series(1, 2500) g;
INSERT INTO sessions (id, user_id, created_at, idle_expires_at, absolute_expires_at, auth_method, revoked_at)
    VALUES ('revoked', 'u1', now() - interval '3 days', now() + interval '1 hour', now() + interval '20 days', 'password', now());
INSERT INTO sessions (id, user_id, created_at, idle_expires_at, absolute_expires_at, auth_method)
    VALUES ('expired', 'u1', now() - interval '40 days', now() - interval '9 days', now() - interval '9 days', 'password');
`); err != nil {
		t.Fatal(err)
	}

	migrate(ctx, t, db)

	var backfilled, untouched int
	if err := st.Maint.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE id LIKE 'live-%' AND authenticated_at = created_at),
		count(*) FILTER (WHERE id IN ('revoked', 'expired') AND authenticated_at = '-infinity')
		FROM sessions`).Scan(&backfilled, &untouched); err != nil {
		t.Fatal(err)
	}
	if backfilled != live {
		t.Errorf("%d of %d live sessions took created_at", backfilled, live)
	}
	if untouched != 2 {
		t.Errorf("%d of the revoked and expired sessions were left at -infinity, want 2", untouched)
	}
	var fresh bool
	if err := st.Maint.QueryRow(ctx, `
INSERT INTO sessions (id, user_id, idle_expires_at, absolute_expires_at, auth_method)
    VALUES ('after', 'u1', now() + interval '1 hour', now() + interval '20 days', 'password')
    RETURNING authenticated_at > now() - interval '1 minute'`).Scan(&fresh); err != nil {
		t.Fatal(err)
	}
	if !fresh {
		t.Error("a session opened after the migration did not default to now()")
	}
}
