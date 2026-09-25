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

// MigrateApplicationName is the application_name of the sessions that run
// migrations. Migration 00033 refuses to copy audit_events while any other
// session of the application is connected, and this is how it tells the
// migrator's own sessions apart.
const MigrateApplicationName = "supermcp-migrate"

// migrateLockPoll is how often a waiting migrator asks for the lock again.
const migrateLockPoll = 500 * time.Millisecond

// errMigrateLockHeld is what a migrator that will not wait reports.
var errMigrateLockHeld = errors.New("another migration is running (advisory lock held)")

// Migrate applies pending migrations under a session-level advisory lock.
// wait controls whether to wait for the lock or fail fast.
//
// A waiting migrator polls pg_try_advisory_lock rather than blocking in
// pg_advisory_lock. A session blocked inside that statement holds a
// snapshot for as long as it waits, and CREATE INDEX CONCURRENTLY waits for
// every snapshot older than its own; with the lock holder running such a
// migration, the two wait on each other through the client, where Postgres
// cannot see the cycle, and neither ever finishes. Between polls the
// waiting session is idle, outside any transaction, and holds nothing.
func (s *Store) Migrate(ctx context.Context, wait bool) error {
	return s.migrate(ctx, wait, true)
}

// MigrateOrWait is Migrate for a serving replica that migrates on start.
// When another process holds the lock it waits for that one to finish and
// then checks the schema, rather than queueing up to migrate after it: if
// migrations are still pending the other migrator failed, and repeating
// its work from every replica in turn is not the answer. It returns an
// error then, and the migrate command, or this replica's next start,
// applies them.
func (s *Store) MigrateOrWait(ctx context.Context) error {
	return s.migrate(ctx, true, false)
}

func (s *Store) migrate(ctx context.Context, wait, afterOthers bool) error {
	// Everything the migration does goes through a pool of its own, named
	// MigrateApplicationName, and this store's idle connections carry the
	// same name until it is done: while it runs, every session of this
	// process is recognisably the migrator's.
	if err := s.nameIdle(ctx, "SET application_name = '"+MigrateApplicationName+"'"); err != nil {
		return fmt.Errorf("migrate: name this process's sessions: %w", err)
	}
	defer func() { //nolint:contextcheck // must run however ctx ended
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.nameIdle(c, "RESET application_name")
	}()
	cfg := s.Maint.Config()
	cfg.ConnConfig.RuntimeParams["application_name"] = MigrateApplicationName
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("migrate pool: %w", err)
	}
	defer pool.Close()

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	waited, err := s.lockMigrations(ctx, conn, wait)
	if err != nil {
		return err
	}
	// Deliberately not ctx: the lock must be released even if the caller's
	// context is already cancelled.
	defer func() { //nolint:contextcheck
		unlock, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlock, "SELECT pg_advisory_unlock($1)", MigrateLockID)
	}()

	db := stdlib.OpenDBFromPool(pool)
	defer func() { _ = db.Close() }()

	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, sub)
	if err != nil {
		return err
	}
	pending, err := provider.HasPending(ctx)
	if err != nil {
		return fmt.Errorf("migrate: check for pending migrations: %w", err)
	}
	if !pending {
		if waited {
			s.log.Info("another migrator brought the schema up to date")
		}
		return nil
	}
	if waited && !afterOthers {
		return errors.New("another migrator held the migration lock and finished with migrations still pending; " +
			"see its logs, then run `supermcp migrate`")
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

// nameIdle runs a SET or RESET of application_name on every idle
// connection of both pools.
func (s *Store) nameIdle(ctx context.Context, stmt string) error {
	for _, pool := range []*pgxpool.Pool{s.App, s.Maint} {
		for _, conn := range pool.AcquireAllIdle(ctx) {
			_, err := conn.Exec(ctx, stmt)
			conn.Release()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// lockMigrations takes the migration lock on conn, which must not be in a
// transaction, polling while someone else holds it. It reports whether it
// had to wait.
func (s *Store) lockMigrations(ctx context.Context, conn *pgxpool.Conn, wait bool) (bool, error) {
	var tick *time.Ticker
	for waited := false; ; waited = true {
		var got bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", MigrateLockID).Scan(&got); err != nil {
			return waited, fmt.Errorf("acquire migrate lock: %w", err)
		}
		if got {
			return waited, nil
		}
		if !wait {
			return false, errMigrateLockHeld
		}
		if tick == nil {
			s.log.Info("another migrator holds the migration lock; waiting for it to finish")
			tick = time.NewTicker(migrateLockPoll)
			defer tick.Stop()
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			return waited, fmt.Errorf("acquire migrate lock: %w", ctx.Err())
		}
	}
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
