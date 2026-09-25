// These tests have the database refuse appends for a while and then take
// them again, which is what a failover or a connection storm looks like
// from the writer. They share the live-Postgres harness in chain_test.go.
package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/tenant"
)

var errRefused = errors.New("the test database is refusing connections")

// flakyDB is the audit test database behind a pool whose new connections
// are refused while refuse says so, or for the next refuseNext of them.
// The pool keeps no idle connection, so each append connects afresh and
// sees the current answer.
type flakyDB struct {
	*tenant.DB
	refuse     atomic.Bool
	refuseNext atomic.Int64
	refused    atomic.Int64
	// firstRefusal is closed on the first refusal, so a test knows the
	// writer is holding a batch without sleeping to find out.
	firstRefusal chan struct{}
}

func newFlakyDB(ctx context.Context, t *testing.T, live *tenant.DB) *flakyDB {
	t.Helper()
	f := &flakyDB{firstRefusal: make(chan struct{})}
	cfg, err := pgxpool.ParseConfig(ownDatabase(ctx, t))
	if err != nil {
		t.Fatalf("parse the audit test database URL: %v", err)
	}
	cfg.MaxConns = 1
	cfg.BeforeConnect = func(context.Context, *pgx.ConnConfig) error {
		if !f.refuse.Load() && f.refuseNext.Add(-1) < 0 {
			return nil
		}
		if f.refused.Add(1) == 1 {
			close(f.firstRefusal)
		}
		return errRefused
	}
	cfg.AfterRelease = func(*pgx.Conn) bool { return false }
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("build the flaky pool: %v", err)
	}
	t.Cleanup(pool.Close)
	f.DB = &tenant.DB{App: live.App, Maint: pool, Log: testLog()}
	return f
}

// gapMarkers reads the gap records written after seq, and removes them
// when the test ends: they carry no organisation, so the stream's own
// purge does not see them.
func gapMarkers(ctx context.Context, t *testing.T, db *tenant.DB, after int64) []map[string]any {
	t.Helper()
	t.Cleanup(func() {
		_ = db.Bypass(context.WithoutCancel(ctx), "audit test cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.WithoutCancel(ctx),
				`DELETE FROM audit_events WHERE action = 'audit.events_dropped' AND seq > $1`, after)
			return err
		})
	})
	var out []map[string]any
	err := db.Bypass(ctx, "audit test gap markers", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT meta FROM audit_events
			WHERE action = 'audit.events_dropped' AND seq > $1 ORDER BY seq`, after)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("reading the gap markers: %v", err)
	}
	return out
}

func headSeq(ctx context.Context, t *testing.T, db *tenant.DB) int64 {
	t.Helper()
	var seq int64
	err := db.Bypass(ctx, "audit test head", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(max(seq), 0) FROM audit_events`).Scan(&seq)
	})
	if err != nil {
		t.Fatalf("reading the head of the stream: %v", err)
	}
	return seq
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// A database that refuses a few appends and then recovers loses nothing,
// under both modes that keep the batch in memory. Before the fix, the
// first refusal dropped the batch with one log line and no record.
func TestARefusedBatchIsRetriedNotDropped(t *testing.T) {
	for _, mode := range []string{audit.UnavailableDegrade, audit.UnavailableBlock} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			live := liveDB(ctx, t)
			s := newStream(ctx, t, live)
			before := headSeq(ctx, t, live)
			db := newFlakyDB(ctx, t, live)

			const refusals = 3
			db.refuseNext.Store(refusals)
			w := audit.NewWriter(db.DB, testLog(), //nolint:contextcheck // the writer appends from its own goroutine
				audit.WithRetry(audit.Options{OnUnavailable: mode}, 20, 10*time.Millisecond))
			defer w.Close()
			for i := range 5 {
				w.Emit(ctx, bare(s.org(), "connector.update", i))
			}
			flushCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := w.Flush(flushCtx); err != nil {
				t.Fatalf("the flush failed although the database came back: %v", err)
			}
			if db.refused.Load() != refusals {
				t.Fatalf("the database refused %d times, want %d: the test did not exercise the retry it meant to", db.refused.Load(), refusals)
			}
			if n := len(s.seqs(ctx)); n != 5 {
				t.Fatalf("the stream holds %d of the 5 events; a refused batch must be retried, not dropped", n)
			}
			if w.Dropped() != 0 || w.DroppedTotal() != 0 {
				t.Fatalf("dropped = %d (total %d), want nothing counted as lost", w.Dropped(), w.DroppedTotal())
			}
			if m := gapMarkers(ctx, t, live, before); len(m) != 0 {
				t.Fatalf("gap markers written: %v; nothing was lost", m)
			}
		})
	}
}

// While a refused batch is held at the head of the queue, the queue fills
// behind it. What does not fit is lost, and the gap marker written when
// the database comes back says how many and which.
func TestAFullQueueRecordsTheGap(t *testing.T) {
	ctx := context.Background()
	live := liveDB(ctx, t)
	s := newStream(ctx, t, live)
	before := headSeq(ctx, t, live)
	db := newFlakyDB(ctx, t, live)

	const buffer, overflow = 4, 3
	db.refuse.Store(true)
	w := audit.NewWriter(db.DB, testLog(), //nolint:contextcheck // the writer appends from its own goroutine
		audit.WithRetry(audit.Options{OnUnavailable: audit.UnavailableDegrade, Buffer: buffer}, 100000, 10*time.Millisecond))
	defer w.Close()

	// The first event is taken off the queue and refused; from then on the
	// writer holds it and reads nothing newer.
	w.Emit(ctx, bare(s.org(), "connector.update", 0))
	waitFor(t, db.firstRefusal, "the database to refuse the first batch")
	for i := range buffer + overflow {
		w.Emit(ctx, bare(s.org(), "connector.update", 1+i))
	}
	if w.Dropped() != overflow {
		t.Fatalf("dropped = %d, want the %d events the full queue could not take", w.Dropped(), overflow)
	}

	db.refuse.Store(false)
	flushCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := w.Flush(flushCtx); err != nil {
		t.Fatalf("the flush failed although the database came back: %v", err)
	}
	if n := len(s.seqs(ctx)); n != 1+buffer {
		t.Fatalf("the stream holds %d events, want the held one and the %d the queue took", n, buffer)
	}
	if w.Dropped() != 0 || w.DroppedTotal() != overflow {
		t.Fatalf("after recovery dropped = %d (total %d), want 0 unreported and %d in all", w.Dropped(), w.DroppedTotal(), overflow)
	}
	markers := gapMarkers(ctx, t, live, before)
	if len(markers) != 1 {
		t.Fatalf("gap markers = %v, want exactly one", markers)
	}
	m := markers[0]
	// The first event is the writer's number 1 and the queue took 2..5,
	// so the lost ones are 6..8.
	if m["events"] != float64(overflow) || m["firstSeq"] != float64(buffer+2) || m["lastSeq"] != float64(buffer+1+overflow) {
		t.Fatalf("gap marker = %v, want %d events numbered %d..%d", m, overflow, buffer+2, buffer+1+overflow)
	}
	if _, ok := m["from"].(string); !ok {
		t.Fatalf("gap marker = %v, want when the lost events were accepted", m)
	}
}

// A database that stays away past the retries: the batch is dropped, and
// the count survives to be written by the next writer that gets through,
// here the same one once the database is back.
func TestRetriesSpentRecordTheGap(t *testing.T) {
	ctx := context.Background()
	live := liveDB(ctx, t)
	s := newStream(ctx, t, live)
	before := headSeq(ctx, t, live)
	db := newFlakyDB(ctx, t, live)

	db.refuse.Store(true)
	w := audit.NewWriter(db.DB, testLog(), //nolint:contextcheck // the writer appends from its own goroutine
		audit.WithRetry(audit.Options{OnUnavailable: audit.UnavailableDegrade}, 3, time.Millisecond))
	defer w.Close()
	for i := range 2 {
		w.Emit(ctx, bare(s.org(), "connector.update", i))
	}
	if err := w.Flush(ctx); err == nil {
		t.Fatal("a flush whose events were dropped reported success")
	}
	if w.Dropped() != 2 {
		t.Fatalf("dropped = %d, want the two refused events counted", w.Dropped())
	}

	db.refuse.Store(false)
	emitSync(ctx, t, w, bare(s.org(), "connector.delete", 0))
	markers := gapMarkers(ctx, t, live, before)
	if len(markers) != 1 || markers[0]["events"] != float64(2) {
		t.Fatalf("gap markers = %v, want one naming the two events", markers)
	}
}
