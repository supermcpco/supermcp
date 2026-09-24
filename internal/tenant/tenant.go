// Package tenant carries the current organisation through a request and
// makes every database access run inside a transaction that has told
// Postgres which tenant it is. Row-level security does the rest.
//
// Rules:
//   - Every query on the app pool goes through Tx. A missing org in the
//     context is a programming error and fails the request.
//   - Cross-tenant and instance-level work goes through Bypass, which uses
//     the maintenance pool and records why.
//   - Pre-authentication lookups use the SECURITY DEFINER auth_* functions
//     on the app pool with Pre.
package tenant

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ctxKey int

const (
	orgKey ctxKey = iota
	bypassKey
)

// ErrNoOrg is returned when a tenant-scoped operation runs without an org.
var ErrNoOrg = errors.New("no organisation in context")

// WithOrg returns a context bound to an organisation.
func WithOrg(ctx context.Context, orgID string) context.Context {
	return context.WithValue(ctx, orgKey, orgID)
}

// OrgID returns the organisation in the context, if any.
func OrgID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(orgKey).(string)
	return v, ok && v != ""
}

// MustOrg returns the org or panics; middleware guarantees it for tenant
// routes, so a panic here is a routing bug caught in tests.
func MustOrg(ctx context.Context) string {
	id, ok := OrgID(ctx)
	if !ok {
		panic(ErrNoOrg)
	}
	return id
}

// DB wraps the two pools.
type DB struct {
	App   *pgxpool.Pool
	Maint *pgxpool.Pool
	Log   *slog.Logger
}

// Tx runs fn in a transaction on the app pool with app.current_org set for
// the transaction's duration. Read-only callers use it too: the cost is one
// SET per transaction and it is the only path that is safe by construction.
func (d *DB) Tx(ctx context.Context, fn func(pgx.Tx) error) error {
	org, ok := OrgID(ctx)
	if !ok {
		return ErrNoOrg
	}
	return pgx.BeginFunc(ctx, d.App, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", org); err != nil {
			return fmt.Errorf("set tenant: %w", err)
		}
		return fn(tx)
	})
}

// Pre runs fn on the app pool with no tenant set, for the SECURITY DEFINER
// auth_* functions only. Any other query returns no rows under RLS.
func (d *DB) Pre(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, d.App, fn)
}

// Bypass runs fn on the maintenance pool, outside row-level security. The
// reason is logged (and later audited); callers must be explicit about
// why they need cross-tenant access.
func (d *DB) Bypass(ctx context.Context, reason string, fn func(pgx.Tx) error) error {
	if reason == "" {
		return errors.New("tenant.Bypass requires a reason")
	}
	if d.Log != nil {
		d.Log.Debug("tenant bypass", "reason", reason)
	}
	ctx = context.WithValue(ctx, bypassKey, reason)
	return pgx.BeginFunc(ctx, d.Maint, fn)
}

// BypassReason reports whether ctx is inside a Bypass and why.
func BypassReason(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(bypassKey).(string)
	return v, ok
}
