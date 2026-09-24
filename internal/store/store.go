// Package store owns the Postgres connection pools and schema migrations.
//
// Two pools exist on purpose: App runs as the row-level-security role and
// cannot bypass tenant policies; Maint runs as the maintenance role for
// migrations, retention and cross-tenant administration. Code that needs
// Maint must go through tenant.Bypass so the reason is audited.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// MigrateLockID is the advisory lock every migrator takes so that replicas
// starting together never race on the schema.
const MigrateLockID int64 = 0x5375706572_4d4350 // "Super" "MCP"

// Store holds both pools.
type Store struct {
	App   *pgxpool.Pool
	Maint *pgxpool.Pool
	log   *slog.Logger
}

// Options tune Open.
type Options struct {
	// AppRole makes every app-pool connection SET ROLE supermcp_app so
	// row-level security applies. serve sets it; migrate does not (the role
	// is created by the migrations themselves).
	AppRole bool
}

// Open connects both pools and pings them.
func Open(ctx context.Context, appURL, maintURL string, log *slog.Logger, opts Options) (*Store, error) {
	var after func(context.Context, *pgx.Conn) error
	if opts.AppRole {
		after = func(ctx context.Context, conn *pgx.Conn) error {
			if _, err := conn.Exec(ctx, "SET ROLE supermcp_app"); err != nil {
				return fmt.Errorf("SET ROLE supermcp_app (run `supermcp migrate` first): %w", err)
			}
			return nil
		}
	}
	app, err := open(ctx, appURL, "app", after)
	if err != nil {
		return nil, err
	}
	// The maintenance pool never switches role even when it shares the URL.
	maint, err := open(ctx, maintURL, "maint", nil)
	if err != nil {
		app.Close()
		return nil, err
	}
	return &Store{App: app, Maint: maint, log: log}, nil
}

func open(ctx context.Context, url, name string, after func(context.Context, *pgx.Conn) error) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("%s pool: %w", name, err)
	}
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second
	cfg.ConnConfig.RuntimeParams["application_name"] = "supermcp-" + name
	cfg.AfterConnect = after
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("%s pool: %w", name, err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("%s pool: ping: %w", name, err)
	}
	return pool, nil
}

// Close releases both pools.
func (s *Store) Close() {
	s.Maint.Close()
	s.App.Close()
}

// Migrate applies pending migrations under a session-level advisory lock.
// wait controls whether to block for the lock or fail fast.
func (s *Store) Migrate(ctx context.Context, wait bool) error {
	conn, err := s.Maint.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if wait {
		if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", MigrateLockID); err != nil {
			return fmt.Errorf("acquire migrate lock: %w", err)
		}
	} else {
		var got bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", MigrateLockID).Scan(&got); err != nil {
			return fmt.Errorf("acquire migrate lock: %w", err)
		}
		if !got {
			return errors.New("another migration is running (advisory lock held)")
		}
	}
	// Deliberately not ctx: the lock must be released even if the caller's
	// context is already cancelled.
	defer func() { //nolint:contextcheck
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", MigrateLockID)
	}()

	db := stdlib.OpenDBFromPool(s.Maint)
	defer func() { _ = db.Close() }()

	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, sub)
	if err != nil {
		return err
	}
	results, err := provider.Up(ctx)
	for _, r := range results {
		s.log.Info("migration applied", "version", r.Source.Version, "path", r.Source.Path, "duration", r.Duration)
	}
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// SchemaVersion returns the newest applied migration version, or 0.
func (s *Store) SchemaVersion(ctx context.Context) (int64, error) {
	var v int64
	err := s.App.QueryRow(ctx, "SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied").Scan(&v)
	if err != nil {
		return 0, err
	}
	return v, nil
}

// LatestVersion is the newest migration compiled into this binary, read
// from the embedded file names (NNNNN_name.sql).
func LatestVersion() (int64, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return 0, err
	}
	var latest int64
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		num, _, ok := strings.Cut(name, "_")
		if !ok {
			continue
		}
		v, err := strconv.ParseInt(num, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("migration %q: bad version prefix", name)
		}
		if v > latest {
			latest = v
		}
	}
	return latest, nil
}
