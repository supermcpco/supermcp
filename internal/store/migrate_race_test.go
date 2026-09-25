package store_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/store"
)

// countingHandler counts "migration applied" records and signals the first
// time a migrator says it is waiting for the lock, so a test can react to
// that without sleeping.
type countingHandler struct {
	applied *atomic.Int64
	waiting chan struct{}
	once    *sync.Once
}

func newCountingLog() (*slog.Logger, *countingHandler) {
	h := &countingHandler{applied: &atomic.Int64{}, waiting: make(chan struct{}), once: &sync.Once{}}
	return slog.New(h), h
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *countingHandler) WithGroup(string) slog.Handler            { return h }
func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	switch {
	case r.Message == "migration applied":
		h.applied.Add(1)
	case strings.Contains(r.Message, "waiting"):
		h.once.Do(func() { close(h.waiting) })
	}
	return nil
}

func migrationCount(t *testing.T) int64 {
	t.Helper()
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			n++
		}
	}
	return n
}

// Replicas that start together on a database that still needs a
// CREATE INDEX CONCURRENTLY migration used to hang: the waiter blocked in
// pg_advisory_lock holding a snapshot, and the concurrent build waited for
// that snapshot while its own migrator held the lock. Postgres cannot see
// that cycle, because it runs through the client. Each case migrates a
// fresh database from two stores at once and must finish well inside the
// deadline.
func TestMigratorsStartingTogetherDoNotHang(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	cases := []struct {
		name   string
		second func(context.Context, *store.Store) error
	}{
		{"two migrate commands", func(ctx context.Context, st *store.Store) error { return st.Migrate(ctx, true) }},
		{"migrate and a serving replica", func(ctx context.Context, st *store.Store) error { return st.MigrateOrWait(ctx) }},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			db := scratchDatabase(ctx, t, dsn, "race_"+string(rune('a'+i)))

			logA, a := newCountingLog()
			logB, b := newCountingLog()
			stA, err := store.Open(ctx, db, db, logA, store.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer stA.Close()
			stB, err := store.Open(ctx, db, db, logB, store.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer stB.Close()

			var wg sync.WaitGroup
			errs := make([]error, 2)
			wg.Add(2)
			go func() { defer wg.Done(); errs[0] = stA.Migrate(ctx, true) }()
			go func() { defer wg.Done(); errs[1] = tc.second(ctx, stB) }()
			wg.Wait()

			if ctx.Err() != nil {
				t.Fatalf("the migrators did not finish within the deadline: they hung (errors: %v, %v)", errs[0], errs[1])
			}
			for i, err := range errs {
				if err != nil {
					t.Fatalf("migrator %d failed: %v", i, err)
				}
			}
			if got, want := a.applied.Load()+b.applied.Load(), migrationCount(t); got != want {
				t.Fatalf("%d migrations applied between the two, want each of the %d applied exactly once", got, want)
			}
		})
	}
}

// Why the waiting migrator polls: a session blocked inside
// SELECT pg_advisory_lock holds a snapshot for as long as it waits, even
// with no transaction open, and CREATE INDEX CONCURRENTLY waits for every
// snapshot older than its own. This pins the premise down, so that a
// future "simplification" back to the blocking call is caught here.
func TestABlockedAdvisoryLockHoldsASnapshot(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db := scratchDatabase(ctx, t, dsn, "snapshot")

	holder, err := pgx.Connect(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close(context.WithoutCancel(ctx)) }()
	waiter, err := pgx.Connect(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = waiter.Close(context.WithoutCancel(ctx)) }()
	observer, err := pgx.Connect(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = observer.Close(context.WithoutCancel(ctx)) }()

	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1)", store.MigrateLockID); err != nil {
		t.Fatal(err)
	}
	waiterPID := waiter.PgConn().PID()
	waitCtx, stopWaiting := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, err := waiter.Exec(waitCtx, "SELECT pg_advisory_lock($1)", store.MigrateLockID)
		done <- err
	}()

	// Watch the waiter from the outside until Postgres reports it waiting
	// on the advisory lock, then read whether it holds a snapshot.
	var holdsSnapshot bool
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		err := observer.QueryRow(ctx, `SELECT wait_event = 'advisory', backend_xmin IS NOT NULL
			FROM pg_stat_activity WHERE pid = $1`, waiterPID).Scan(&waiting, &holdsSnapshot)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("the waiter never showed up waiting on the advisory lock")
		}
	}
	stopWaiting()
	<-done
	if !holdsSnapshot {
		t.Fatal("a session blocked in pg_advisory_lock held no snapshot; the polling in Migrate may no longer be needed")
	}
}

// A serving replica that finds another migrator at work waits for it and
// does not migrate after it. When the other finished the job, it carries
// on without applying anything.
func TestMigrateOrWaitWaitsForTheHolder(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db := scratchDatabase(ctx, t, dsn, "orwait")
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	cases := []struct {
		name         string
		migrateFirst bool
		wantErr      bool
	}{
		// Order matters: the second case needs the schema the first leaves
		// unapplied, so the pending case runs first.
		{name: "the holder left migrations pending", migrateFirst: false, wantErr: true},
		{name: "the holder finished", migrateFirst: true, wantErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.migrateFirst {
				st, err := store.Open(ctx, db, db, quiet, store.Options{})
				if err != nil {
					t.Fatal(err)
				}
				err = st.Migrate(ctx, true)
				st.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			holder, err := pgx.Connect(ctx, db)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = holder.Close(context.WithoutCancel(ctx)) }()
			if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1)", store.MigrateLockID); err != nil {
				t.Fatal(err)
			}

			log, h := newCountingLog()
			st, err := store.Open(ctx, db, db, log, store.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			done := make(chan error, 1)
			go func() { done <- st.MigrateOrWait(ctx) }()

			select {
			case <-h.waiting:
			case err := <-done:
				t.Fatalf("MigrateOrWait returned (%v) while another session held the lock", err)
			case <-ctx.Done():
				t.Fatal("MigrateOrWait never said it was waiting")
			}
			if _, err := holder.Exec(ctx, "SELECT pg_advisory_unlock($1)", store.MigrateLockID); err != nil {
				t.Fatal(err)
			}
			err = <-done
			if tc.wantErr && err == nil {
				t.Fatal("MigrateOrWait succeeded although the schema is behind; it must not migrate after another migrator")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("MigrateOrWait failed after the holder brought the schema up to date: %v", err)
			}
			if n := h.applied.Load(); n != 0 {
				t.Fatalf("MigrateOrWait applied %d migrations after waiting; it must leave that to the holder", n)
			}
		})
	}
}
