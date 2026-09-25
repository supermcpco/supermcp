// These tests exercise the audit trail against a live Postgres, because the
// hash chain is a property of rows in a table, of the bytes the columns give
// back, and of the order in which they were written; none of that survives a
// fake. Set DATABASE_URL to run them.
package audit_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/sync/errgroup"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
	"github.com/supermcpco/supermcp/internal/testdb"
)

// ---------------------------------------------------------------------------
// harness

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// auditTestDB is a database of this package's own. A retention cut is
// instance-wide by design — every organisation's events share one
// sequence — so these tests need an instance nobody else is writing to.
// Sharing the development database with the other packages' tests, which
// `go test ./...` runs at the same time, made a cut delete rows the
// verifier then reported as a broken chain. The name carries this
// checkout's suffix (internal/testdb), so another worktree's run is not
// that neighbour either.
var auditTestDB = testdb.Name("supermcp_audit_tests")

// liveDB opens both pools against a database of this package's own,
// created beside the one DATABASE_URL names. The app pool runs as the
// row-level-security role, which is the role Reader.List has to work
// under.
func liveDB(ctx context.Context, t *testing.T) *tenant.DB {
	t.Helper()
	url := ownDatabase(ctx, t)
	// The schema is applied as the maintenance role first, because it is
	// what creates the row-level-security role the next pool asks for. A
	// cluster that has never run a migration has no such role, and
	// opening with it would fail on the first ping.
	maint, err := store.Open(ctx, url, url, testLog(), store.Options{})
	if err != nil {
		t.Fatalf("could not open %s: %v", auditTestDB, err)
	}
	if err := maint.Migrate(ctx, true); err != nil {
		maint.Close()
		t.Fatalf("could not apply the schema to %s: %v", auditTestDB, err)
	}
	maint.Close()

	st, err := store.Open(ctx, url, url, testLog(), store.Options{AppRole: true})
	if err != nil {
		t.Fatalf("could not open the app and maintenance pools against DATABASE_URL, so no audit test can run: %v", err)
	}
	t.Cleanup(st.Close)
	return &tenant.DB{App: st.App, Maint: st.Maint, Log: testLog()}
}

// ownDatabase creates the package's database if it is not there and
// returns its URL. It is left behind between runs on purpose: creating it
// costs a second, and a developer who wants it gone can drop it.
func ownDatabase(ctx context.Context, t *testing.T) string {
	t.Helper()
	return testdb.Own(ctx, t, os.Getenv("DATABASE_URL"), auditTestDB)
}

// stream is one test's slice of the shared audit_events table: its own
// organisation ids and the widest seq range they have ever occupied. It
// purges both on the way in and on the way out, so a run that crashed
// half-way cannot fail the next one.
type stream struct {
	t    *testing.T
	db   *tenant.DB
	orgs []string
	lo   int64
	hi   int64
}

var orgSafe = strings.NewReplacer("/", "_", " ", "_", "#", "_", ",", "_")

func newStream(ctx context.Context, t *testing.T, db *tenant.DB, suffixes ...string) *stream {
	t.Helper()
	s := &stream{t: t, db: db}
	base := "audit_t_" + orgSafe.Replace(t.Name())
	if len(suffixes) == 0 {
		suffixes = []string{""}
	}
	for _, suffix := range suffixes {
		s.orgs = append(s.orgs, base+suffix)
	}
	s.purge(ctx)
	t.Cleanup(func() { s.purge(context.WithoutCancel(ctx)) })
	return s
}

// org is the tenant a single-tenant test writes to.
func (s *stream) org() string { return s.orgs[0] }

// bounds returns the seq range this test's events occupy, widened by every
// range seen so far. Cut leaves an anchor at a seq whose event is gone, so
// cleanup needs the range from before the cut, not after it.
func (s *stream) bounds(ctx context.Context) (int64, int64) {
	s.t.Helper()
	var lo, hi *int64
	err := s.db.Bypass(ctx, "audit test bounds", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT min(seq), max(seq) FROM audit_events WHERE organization_id = ANY($1)`, s.orgs).Scan(&lo, &hi)
	})
	if err != nil {
		s.t.Fatalf("could not read back the seq range for %v: %v", s.orgs, err)
	}
	if lo != nil {
		if s.lo == 0 || *lo < s.lo {
			s.lo = *lo
		}
		if *hi > s.hi {
			s.hi = *hi
		}
	}
	return s.lo, s.hi
}

// seqs lists this test's event sequences, oldest first.
func (s *stream) seqs(ctx context.Context) []int64 {
	s.t.Helper()
	var out []int64
	err := s.db.Bypass(ctx, "audit test seqs", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT seq FROM audit_events WHERE organization_id = ANY($1) ORDER BY seq`, s.orgs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var seq int64
			if err := rows.Scan(&seq); err != nil {
				return err
			}
			out = append(out, seq)
		}
		return rows.Err()
	})
	if err != nil {
		s.t.Fatalf("could not list the event sequences for %v: %v", s.orgs, err)
	}
	return out
}

func (s *stream) purge(ctx context.Context) {
	lo, hi := s.bounds(ctx)
	err := s.db.Bypass(ctx, "audit test cleanup", func(tx pgx.Tx) error {
		if lo > 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM audit_anchors WHERE seq BETWEEN $1 AND $2`, lo, hi); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `DELETE FROM audit_events WHERE organization_id = ANY($1)`, s.orgs)
		return err
	})
	if err != nil {
		s.t.Fatalf("could not remove the rows this test wrote for %v; a rerun will not be clean: %v", s.orgs, err)
	}
}

// maintExec runs a statement as the maintenance role: after migration 00006
// the app role may only null a scrubbed row's content, so the maintenance
// role is the only way to stage the tampering these tests are about.
func maintExec(ctx context.Context, t *testing.T, db *tenant.DB, sql string, args ...any) int64 {
	t.Helper()
	var affected int64
	err := db.Bypass(ctx, "audit test maintenance", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, sql, args...)
		affected = tag.RowsAffected()
		return err
	})
	if err != nil {
		t.Fatalf("could not run %q as the maintenance role: %v", sql, err)
	}
	return affected
}

func emitSync(ctx context.Context, t *testing.T, w *audit.Writer, e audit.Event) {
	t.Helper()
	if err := w.EmitSync(ctx, e); err != nil {
		t.Fatalf("appending %s/%s for org %s to the audit chain failed: %v", e.Category, e.Action, e.OrgID, err)
	}
}

// event builds one event carrying the three JSON bodies a real one carries.
// Nearly every event does: an admin change has a diff, a tool call has a
// payload, everything has request metadata. Keys are chosen so that Go's
// alphabetical ordering and jsonb's length ordering disagree, which is the
// shape that used to make every such event verify as tampered.
func event(org, action string, n int) audit.Event {
	return audit.Event{
		OrgID:      org,
		Category:   audit.CategoryAdmin,
		Action:     action,
		Outcome:    audit.Success,
		ActorKind:  "user",
		ActorID:    "u_chain",
		TargetKind: "connector",
		TargetID:   fmt.Sprintf("c_%02d", n),
		Diff: audit.Changes(
			map[string]any{"name": "prod", "timeoutSeconds": n},
			map[string]any{"name": "prod", "timeoutSeconds": n + 1},
		),
		Payload: map[string]any{"input": map[string]any{"q": "hello", "n": n}},
		Meta:    map[string]any{"z": n, "requestId": fmt.Sprintf("req_%02d", n), "aVeryLongKeyName": true},
	}
}

// bare builds an event with no JSON bodies at all, so that a test about the
// links is not also a test about the content digest.
func bare(org, action string, n int) audit.Event {
	e := event(org, action, n)
	e.Diff, e.Payload, e.Meta = nil, nil, nil
	return e
}

// ---------------------------------------------------------------------------
// 1. a batch of appends links into a chain

func TestChainLinksABatchOfAppendedEvents(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db)
	w := audit.NewWriter(db, testLog(), audit.Options{})
	defer w.Close()

	// Emit plus Flush is the path every request handler takes: queue, batch,
	// one transaction, one advisory lock. If the chain only held for the
	// one-event EmitSync path, the product would be broken under load.
	const events = 6
	for i := range events {
		w.Emit(ctx, event(s.org(), "connector.update", i))
	}
	if err := w.Flush(ctx); err != nil {
		t.Fatalf("flushing %d queued events failed, so nothing could be verified: %v", events, err)
	}

	lo, hi := s.bounds(ctx)
	if lo == 0 {
		t.Fatalf("Emit followed by Flush wrote nothing: %d events were queued for org %s and none reached audit_events", events, s.org())
	}

	r := &audit.Reader{DB: db}
	res, err := r.Verify(ctx, lo, hi)
	if err != nil {
		t.Fatalf("Verify over seq %d..%d failed before it could reach a verdict: %v", lo, hi, err)
	}
	if !res.Valid {
		t.Fatalf("a chain of %d events that nothing has touched since it was written reports as broken at seq %d (%q); it should be intact over seq %d..%d",
			events, res.BrokenAt, res.Explained, lo, hi)
	}
	if res.Checked != events {
		t.Errorf("Verify walked %d rows over seq %d..%d but %d events were appended there; the walk is skipping rows it should be checking",
			res.Checked, lo, hi, events)
	}
	if res.Scrubbed != 0 {
		t.Errorf("Verify reports %d rows as scrubbed, but nothing has been scrubbed; an auditor would be told content is missing when it is not", res.Scrubbed)
	}
	if res.FirstSeq != lo || res.LastSeq != hi {
		t.Errorf("Verify reports it covered seq %d..%d, but the events occupy seq %d..%d; an auditor would think part of the range went unchecked",
			res.FirstSeq, res.LastSeq, lo, hi)
	}

	// SeqRange is how a tenant finds the stretch of chain to ask about, and
	// it runs under row-level security rather than the maintenance role.
	first, last, err := r.SeqRange(ctx, s.org())
	if err != nil {
		t.Fatalf("SeqRange for org %s failed: %v", s.org(), err)
	}
	if first != lo || last != hi {
		t.Errorf("SeqRange reports %d..%d for org %s, but its events occupy %d..%d", first, last, s.org(), lo, hi)
	}
	if first, last, err := r.SeqRange(ctx, "audit_t_nobody"); err != nil || first != 0 || last != 0 {
		t.Errorf("SeqRange for an organisation that has never written an event reports %d..%d (err %v); it should report 0..0 rather than another tenant's range",
			first, last, err)
	}
}

// 1b. The bodies are the regression this whole design exists for: the chain
// used to hash the JSON the writer serialised and then rehash what Postgres
// handed back, which is never the same bytes once jsonb has normalised it.
func TestChainLinksEventsCarryingJSONBodies(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db)
	w := audit.NewWriter(db, testLog(), audit.Options{})
	defer w.Close()

	full := event(s.org(), "connector.update", 0)
	emitSync(ctx, t, w, full)
	emitSync(ctx, t, w, bare(s.org(), "session.create", 1)) // a neighbour with no bodies at all

	lo, hi := s.bounds(ctx)
	r := &audit.Reader{DB: db}
	res, err := r.Verify(ctx, lo, hi)
	if err != nil {
		t.Fatalf("Verify over seq %d..%d failed before it could reach a verdict: %v", lo, hi, err)
	}
	if !res.Valid {
		var stored string
		if err := db.Bypass(ctx, "audit test render", func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT meta::text FROM audit_events WHERE seq = $1`, lo).Scan(&stored)
		}); err != nil {
			stored = "(could not read it back: " + err.Error() + ")"
		}
		t.Fatalf("an event carrying a diff, a payload and metadata reports as broken at seq %d (%q) although nobody touched it.\n"+
			"The meta it was written with reads back from the database as %s. If that is not byte-for-byte what the writer marshalled, "+
			"the JSON columns are being normalised on the way in and the content digest cannot survive the round trip.",
			res.BrokenAt, res.Explained, strconv.Quote(stored))
	}

	// The content has to be readable as well as verifiable: a digest that
	// matches nothing anyone can read is not an audit trail.
	got, err := r.List(ctx, audit.Query{OrgID: s.org(), Action: "connector.update"})
	if err != nil {
		t.Fatalf("listing the event back failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected the single connector.update event back, got %d", len(got))
	}
	if got[0].Meta["requestId"] != "req_00" {
		t.Errorf("the event was written with meta.requestId %q but reads back as %#v; a reader cannot correlate it with its request",
			"req_00", got[0].Meta)
	}
	if got[0].Diff == nil || got[0].Payload == nil {
		t.Errorf("the event was written with a diff and a payload but reads back with diff %#v and payload %#v",
			got[0].Diff, got[0].Payload)
	}
}

// ---------------------------------------------------------------------------
// 2. an edit after the fact is caught

func TestVerifyCatchesAnEditAfterTheFact(t *testing.T) {
	cases := []struct {
		name       string
		set        string // the SET clause staged through the maintenance role
		wantBroken bool
		explains   string // what the verdict has to say, so a reader can act on it
		why        string // why a lawful edit must be tolerated
	}{
		// The columns that say what happened are the ones an attacker would
		// rewrite, so all of them are inside the row's own hash.
		{name: "action", set: `action = 'connector.read'`, wantBroken: true, explains: "was modified after it was written"},
		{name: "outcome", set: `outcome = 'denied'`, wantBroken: true, explains: "was modified after it was written"},
		{name: "actor", set: `actor_id = 'u_someone_else'`, wantBroken: true, explains: "was modified after it was written"},
		{name: "target", set: `target_id = 'c_99'`, wantBroken: true, explains: "was modified after it was written"},
		{name: "category", set: `category = 'system'`, wantBroken: true, explains: "was modified after it was written"},
		// The chain covers the content through its digest, so rewriting the
		// digest is just another edit to a hashed column.
		{name: "content digest", set: `content_hash = '\x00'`, wantBroken: true, explains: "was modified after it was written"},
		// ...and rewriting the content itself has to be caught even though
		// the content is not in the row hash directly.
		{name: "diff", set: `diff = '{"after":{"timeoutSeconds":999}}'::json`, wantBroken: true, explains: "content of row"},
		{name: "payload", set: `payload = '{"input":{"q":"something else"}}'::json`, wantBroken: true, explains: "content of row"},
		{name: "meta", set: `meta = '{"requestId":"req_forged"}'::json`, wantBroken: true, explains: "content of row"},
		// These sit outside the hash on purpose, so that pseudonymising a
		// departed employee or placing a row under legal hold stays lawful
		// without destroying the chain.
		{name: "actor display", set: `actor_display = 'pseudonymised'`,
			why: "pseudonymising a display name is a lawful edit and must not invalidate the chain"},
		{name: "target display", set: `target_display = 'pseudonymised'`,
			why: "pseudonymising a target name is a lawful edit and must not invalidate the chain"},
		{name: "legal hold", set: `legal_hold = true`,
			why: "placing a row under legal hold is a lawful edit and must not invalidate the chain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := liveDB(ctx, t)
			s := newStream(ctx, t, db)
			w := audit.NewWriter(db, testLog(), audit.Options{}) //nolint:contextcheck // the writer appends from its own goroutine
			defer w.Close()

			for i := range 5 {
				emitSync(ctx, t, w, event(s.org(), "connector.update", i))
			}
			seqs := s.seqs(ctx)
			if len(seqs) != 5 {
				t.Fatalf("expected 5 appended events for org %s, found %d", s.org(), len(seqs))
			}
			lo, hi := s.bounds(ctx)
			target := seqs[2] // the middle, so a break is neither the first nor the last row

			//nolint:gosec // the SET clause comes from this table, never from input.
			if n := maintExec(ctx, t, db, fmt.Sprintf("UPDATE audit_events SET %s WHERE seq = $1", tc.set), target); n != 1 {
				t.Fatalf("staging the edit changed %d rows, wanted exactly 1 at seq %d", n, target)
			}

			r := &audit.Reader{DB: db}
			res, err := r.Verify(ctx, lo, hi)
			if err != nil {
				t.Fatalf("Verify over seq %d..%d failed before it could reach a verdict: %v", lo, hi, err)
			}
			if !tc.wantBroken {
				if !res.Valid {
					t.Fatalf("running `SET %s` on seq %d reports the chain as broken at seq %d (%q), but %s",
						tc.set, target, res.BrokenAt, res.Explained, tc.why)
				}
				return
			}
			if res.Valid {
				t.Fatalf("seq %d was rewritten with `SET %s` after the row was written, and Verify still reports seq %d..%d as intact; an edit the chain covers has to be detectable",
					target, tc.set, lo, hi)
			}
			if res.BrokenAt != target {
				t.Errorf("Verify blames seq %d, but `SET %s` was run on seq %d; an auditor sent to the wrong row cannot act on the report",
					res.BrokenAt, tc.set, target)
			}
			if !strings.Contains(res.Explained, tc.explains) {
				t.Errorf("the verdict on seq %d reads %q; it should say %q so the reader knows what kind of edit happened",
					target, res.Explained, tc.explains)
			}
			if !strings.Contains(res.Explained, strconv.FormatInt(res.BrokenAt, 10)) {
				t.Errorf("the verdict %q does not name the sequence that broke (%d), so it does not tell the reader where to look",
					res.Explained, res.BrokenAt)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. a deletion is caught

func TestVerifyCatchesADeletedRow(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db)
	w := audit.NewWriter(db, testLog(), audit.Options{})
	defer w.Close()

	for i := range 5 {
		emitSync(ctx, t, w, event(s.org(), "connector.update", i))
	}
	seqs := s.seqs(ctx)
	lo, hi := s.bounds(ctx)
	removed := seqs[2]

	// Removing the record of one action is the cheapest way to hide it, so
	// this is the case the chain exists for.
	if n := maintExec(ctx, t, db, `DELETE FROM audit_events WHERE seq = $1`, removed); n != 1 {
		t.Fatalf("deleting seq %d removed %d rows, wanted exactly 1", removed, n)
	}

	r := &audit.Reader{DB: db}
	res, err := r.Verify(ctx, lo, hi)
	if err != nil {
		t.Fatalf("Verify over seq %d..%d failed before it could reach a verdict: %v", lo, hi, err)
	}
	if res.Valid {
		t.Fatalf("seq %d was deleted from the middle of the chain and Verify still reports seq %d..%d as intact; the chain would hide a removed event",
			removed, lo, hi)
	}
	// The hole shows up at the row that still points to the deleted one.
	if res.BrokenAt != seqs[3] {
		t.Errorf("Verify blames seq %d, but seq %d was deleted and seq %d is the first row whose predecessor is missing",
			res.BrokenAt, removed, seqs[3])
	}
	if !strings.Contains(res.Explained, strconv.FormatInt(res.BrokenAt, 10)) {
		t.Errorf("the verdict %q does not name the sequence that broke (%d), so it does not tell the reader where to look",
			res.Explained, res.BrokenAt)
	}
}

// ---------------------------------------------------------------------------
// 4. retention: a lawful cut and a lawful scrub are not breaks
//
// If retention looked the same as tampering, every deployment with a
// retention policy would report a broken chain for ever and the signal
// would be worthless.

func TestCutLeavesTheRemainingChainVerifiable(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db)
	w := audit.NewWriter(db, testLog(), audit.Options{})
	defer w.Close()

	r := &audit.Reader{DB: db}
	// Retention runs on a timer against streams where nothing has aged out
	// yet, so the empty case has to be a quiet no-op.
	if deleted, err := r.Cut(ctx, time.Now().Add(-100*365*24*time.Hour)); err != nil || deleted != 0 {
		t.Fatalf("cutting at a date no event predates removed %d rows (err %v); it should have found nothing to do", deleted, err)
	}

	// The timestamp is covered by the hash, so a stream that needs to look
	// old is written by a writer whose clock is in the past rather than by
	// editing rows afterwards, which is tampering and is caught.
	old := audit.NewWriter(db, testLog(), audit.Options{Now: func() time.Time { return time.Now().Add(-48 * time.Hour) }})
	for i := range 5 {
		emitSync(ctx, t, old, event(s.org(), "connector.update", i))
	}
	old.Close()
	for i := 5; i < 10; i++ {
		emitSync(ctx, t, w, event(s.org(), "connector.update", i))
	}
	seqs := s.seqs(ctx)
	lo, hi := s.bounds(ctx)
	cut := seqs[4]

	deleted, err := r.Cut(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("cutting events older than 24h failed: %v", err)
	}
	if deleted < 5 {
		t.Fatalf("Cut removed %d events, but the 5 events up to seq %d were aged past the 24h window", deleted, cut)
	}

	var kind string
	if err := db.Bypass(ctx, "audit test anchor", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT kind FROM audit_anchors WHERE seq = $1`, cut).Scan(&kind)
	}); err != nil {
		t.Fatalf("Cut left no anchor at seq %d, the last event it removed, so nothing can bridge the cut: %v", cut, err)
	}
	if kind != "retention_cut" {
		t.Errorf("the anchor at seq %d has kind %q; Verify only bridges a cut recorded as \"retention_cut\"", cut, kind)
	}

	res, err := r.Verify(ctx, lo, hi)
	if err != nil {
		t.Fatalf("Verify over seq %d..%d failed before it could reach a verdict: %v", lo, hi, err)
	}
	if !res.Valid {
		t.Fatalf("after retention cut seq %d..%d away, Verify reports the surviving chain as broken at seq %d (%q); the retention_cut anchor at seq %d exists to bridge exactly this",
			lo, cut, res.BrokenAt, res.Explained, cut)
	}
	if res.Checked != 5 {
		t.Errorf("Verify walked %d surviving rows, but 5 of the 10 events were kept", res.Checked)
	}
	if res.FirstSeq != seqs[5] {
		t.Errorf("Verify starts at seq %d, but the oldest surviving event is seq %d", res.FirstSeq, seqs[5])
	}
}

func TestCutStopsAtALegalHold(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db)
	w := audit.NewWriter(db, testLog(), audit.Options{})
	defer w.Close()

	// All six rows are old enough to cut; what stops the cut is the hold,
	// not the age. The clock is injected because the timestamp is hashed.
	old := audit.NewWriter(db, testLog(), audit.Options{Now: func() time.Time { return time.Now().Add(-48 * time.Hour) }})
	for i := range 6 {
		emitSync(ctx, t, old, event(s.org(), "connector.update", i))
	}
	old.Close()
	seqs := s.seqs(ctx)
	lo, hi := s.bounds(ctx)
	held := seqs[3]

	// A legal hold is one of the few edits the chain deliberately does not
	// cover, since placing one must not invalidate the record it protects.
	maintExec(ctx, t, db, `UPDATE audit_events SET legal_hold = true WHERE seq = $1`, held)

	// Skipping the held row and deleting around it would tear the chain, so
	// the cut has to stop at it and leave the newer rows alone as well.
	r := &audit.Reader{DB: db}
	deleted, err := r.Cut(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("cutting a stream with a row under legal hold failed: %v", err)
	}
	if deleted != 3 {
		t.Errorf("Cut removed %d events; it should have stopped below the legal hold at seq %d and removed the 3 rows before it", deleted, held)
	}

	survivors := s.seqs(ctx)
	if len(survivors) != 3 || survivors[0] != held {
		t.Fatalf("after the cut the surviving sequences are %v; the row under legal hold (seq %d) and the two after it should be exactly what is left",
			survivors, held)
	}
	res, err := r.Verify(ctx, lo, hi)
	if err != nil {
		t.Fatalf("Verify over seq %d..%d failed before it could reach a verdict: %v", lo, hi, err)
	}
	if !res.Valid {
		t.Errorf("stopping the cut at the legal hold at seq %d still left the chain broken at seq %d (%q)", held, res.BrokenAt, res.Explained)
	}
}

func TestScrubRemovesContentAndLeavesTheChain(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db, "_a", "_b")
	w := audit.NewWriter(db, testLog(), audit.Options{})
	defer w.Close()

	// Two tenants sharing one sequence is the normal case, and the reason
	// scrubbing exists: one tenant's shorter window cannot delete rows out
	// of the middle of a chain the other tenant also relies on.
	orgA, orgB := s.orgs[0], s.orgs[1]
	// Org A's events are two days old and org B's are current, written by
	// two writers rather than edited afterwards, because the timestamp is
	// part of what the chain covers.
	old := audit.NewWriter(db, testLog(), audit.Options{Now: func() time.Time { return time.Now().Add(-48 * time.Hour) }})
	for i := range 4 {
		emitSync(ctx, t, old, event(orgA, "connector.update", i))
		emitSync(ctx, t, w, event(orgB, "connector.update", i))
	}
	old.Close()
	lo, hi := s.bounds(ctx)

	r := &audit.Reader{DB: db}
	scrubbed, err := r.Scrub(ctx, orgA, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("scrubbing the content of %s's older events failed: %v", orgA, err)
	}
	if scrubbed != 4 {
		t.Fatalf("Scrub touched %d of org A's 4 aged events", scrubbed)
	}
	// Retention runs on a timer and will meet rows it has already scrubbed.
	if again, err := r.Scrub(ctx, orgA, time.Now().Add(-24*time.Hour)); err != nil || again != 0 {
		t.Errorf("scrubbing the same events a second time touched %d rows (err %v); it should be a no-op", again, err)
	}

	// The content has to be really gone, not merely hidden from the reader.
	var left int
	if err := db.Bypass(ctx, "audit test scrubbed", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_events
			WHERE organization_id = $1 AND (diff IS NOT NULL OR payload IS NOT NULL OR scrubbed_at IS NULL)`, orgA).Scan(&left)
	}); err != nil {
		t.Fatalf("could not check what the scrub left behind: %v", err)
	}
	if left != 0 {
		t.Errorf("%d of org A's rows still hold a diff or a payload, or were not marked as scrubbed; a scrub that leaves the content behind honours nothing", left)
	}
	if got, err := r.List(ctx, audit.Query{OrgID: orgA}); err != nil {
		t.Fatalf("listing org A's scrubbed events failed: %v", err)
	} else {
		for _, rec := range got {
			if rec.Diff != nil || rec.Payload != nil {
				t.Errorf("seq %d reads back with diff %#v and payload %#v after being scrubbed", rec.Seq, rec.Diff, rec.Payload)
			}
		}
	}

	res, err := r.Verify(ctx, lo, hi)
	if err != nil {
		t.Fatalf("Verify over seq %d..%d failed before it could reach a verdict: %v", lo, hi, err)
	}
	if !res.Valid {
		t.Fatalf("scrubbing one tenant's content broke the chain at seq %d (%q); a scrubbed row keeps its digest and its place, so the links either side of it still have to hold",
			res.BrokenAt, res.Explained)
	}
	if res.Checked != 8 {
		t.Errorf("Verify walked %d rows, but all 8 events are still in the chain", res.Checked)
	}
	// Saying which rows could not be checked is more honest than a bare
	// "valid": their content is no longer there to compare against.
	if res.Scrubbed != 4 {
		t.Errorf("Verify reports %d scrubbed rows, but 4 rows had their content removed; an auditor needs to know which rows it could only check the links of", res.Scrubbed)
	}
	// Org B never asked for a scrub and must still be fully verifiable.
	var untouched int
	if err := db.Bypass(ctx, "audit test untouched", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id = $1 AND diff IS NOT NULL AND scrubbed_at IS NULL`, orgB).Scan(&untouched)
	}); err != nil {
		t.Fatalf("could not check org B's rows: %v", err)
	}
	if untouched != 4 {
		t.Errorf("scrubbing org A left only %d of org B's 4 events intact; a scrub must not reach into another tenant", untouched)
	}
}

// ---------------------------------------------------------------------------
// 5. anchoring

func TestAnchorRecordsTheHeadAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db)
	w := audit.NewWriter(db, testLog(), audit.Options{})
	defer w.Close()

	for i := range 3 {
		emitSync(ctx, t, w, event(s.org(), "connector.update", i))
	}
	_, head := s.bounds(ctx)

	var headHash []byte
	if err := db.Bypass(ctx, "audit test head", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT hash FROM audit_events WHERE seq = $1`, head).Scan(&headHash)
	}); err != nil {
		t.Fatalf("could not read the head hash at seq %d: %v", head, err)
	}

	r := &audit.Reader{DB: db}
	var signed [][]byte
	sign := func(b []byte) (string, error) {
		signed = append(signed, b)
		return "sig-" + strconv.Itoa(len(signed)), nil
	}
	if err := r.Anchor(ctx, sign); err != nil {
		t.Fatalf("anchoring the chain at seq %d failed: %v", head, err)
	}
	if len(signed) != 1 {
		t.Fatalf("Anchor called the signer %d times for one checkpoint, wanted 1", len(signed))
	}
	if hex.EncodeToString(signed[0]) != hex.EncodeToString(headHash) {
		t.Errorf("Anchor asked the signer to sign %x, but the head of the chain at seq %d hashes to %x; a checkpoint over the wrong hash proves nothing",
			signed[0], head, headHash)
	}

	type anchor struct {
		count int
		kind  string
		sig   string
	}
	read := func() anchor {
		t.Helper()
		var a anchor
		if err := db.Bypass(ctx, "audit test anchor", func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*), coalesce(max(kind),''), coalesce(max(signature),'') FROM audit_anchors WHERE seq = $1`, head).Scan(&a.count, &a.kind, &a.sig)
		}); err != nil {
			t.Fatalf("could not read the anchors at seq %d: %v", head, err)
		}
		return a
	}
	first := read()
	if first.count != 1 {
		t.Fatalf("Anchor left %d rows at seq %d, wanted exactly 1 checkpoint", first.count, head)
	}
	if first.kind != "checkpoint" {
		t.Errorf("the anchor at seq %d has kind %q, wanted \"checkpoint\"; retention bridging keys off the kind", head, first.kind)
	}
	if first.sig != "sig-1" {
		t.Errorf("the anchor at seq %d stored signature %q, but the signer returned \"sig-1\"", head, first.sig)
	}

	// Anchoring runs on a timer, so it will meet a head it has already
	// checkpointed. That must be a no-op, not a second row or an overwrite.
	if err := r.Anchor(ctx, sign); err != nil {
		t.Fatalf("anchoring a head that was already anchored failed instead of doing nothing: %v", err)
	}
	second := read()
	if second.count != 1 {
		t.Errorf("anchoring the same head twice left %d rows at seq %d; a checkpoint must be idempotent", second.count, head)
	}
	if second.sig != first.sig {
		t.Errorf("anchoring the same head twice replaced the published signature %q with %q", first.sig, second.sig)
	}
}

// ---------------------------------------------------------------------------
// 6. reading the stream back

func TestListFiltersAndPages(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db, "", "_other")
	w := audit.NewWriter(db, testLog(), audit.Options{})
	defer w.Close()

	org := s.org()
	seeded := []audit.Event{
		{OrgID: org, Category: audit.CategoryAuth, Action: "session.create", Outcome: audit.Success, ActorKind: "user", ActorID: "u_ada",
			IP: "203.0.113.10"},
		// A caller behind a proxy that sent something unparseable must still
		// be recorded; losing the event is worse than losing the address.
		{OrgID: org, Category: audit.CategoryAuth, Action: "session.create", Outcome: audit.Failure, ActorKind: "user", ActorID: "u_bob",
			IP: "not-an-address"},
		{OrgID: org, Category: audit.CategoryAdmin, Action: "connector.update", Outcome: audit.Success, ActorKind: "user", ActorID: "u_ada",
			TargetKind: "connector", TargetID: "c_1", Meta: map[string]any{"requestId": "req_7"}},
		{OrgID: org, Category: audit.CategoryAdmin, Action: "connector.delete", Outcome: audit.Denied, ActorKind: "user", ActorID: "u_ada",
			TargetKind: "connector", TargetID: "c_1"},
		{OrgID: org, Category: audit.CategoryTool, Action: "tool.invoke", Outcome: audit.Success, ActorKind: "service_account", ActorID: "u_bob"},
		{OrgID: org, Category: audit.CategoryTool, Action: "tool.invoke", Outcome: audit.Success, ActorKind: "user", ActorID: "u_ada"},
		// A neighbouring tenant on the same chain, which must never appear.
		{OrgID: s.orgs[1], Category: audit.CategoryAdmin, Action: "connector.update", Outcome: audit.Success, ActorKind: "user", ActorID: "u_ada"},
	}
	for _, e := range seeded {
		emitSync(ctx, t, w, e)
	}
	s.bounds(ctx) // record the range so cleanup can find it again
	r := &audit.Reader{DB: db}

	// Action, actor and outcome together are what distinguish the seeded
	// events from one another.
	key := func(rec audit.Record) string { return rec.Action + "/" + rec.ActorID + "/" + rec.Outcome }
	cases := []struct {
		name string
		q    audit.Query
		want []string
	}{
		{
			name: "no filter returns the tenant's own events only",
			q:    audit.Query{OrgID: org},
			want: []string{
				"tool.invoke/u_ada/success", "tool.invoke/u_bob/success",
				"connector.delete/u_ada/denied", "connector.update/u_ada/success",
				"session.create/u_bob/failure", "session.create/u_ada/success",
			},
		},
		{
			name: "category",
			q:    audit.Query{OrgID: org, Category: audit.CategoryAdmin},
			want: []string{"connector.delete/u_ada/denied", "connector.update/u_ada/success"},
		},
		{
			name: "action",
			q:    audit.Query{OrgID: org, Action: "session.create"},
			want: []string{"session.create/u_bob/failure", "session.create/u_ada/success"},
		},
		{
			name: "actor",
			q:    audit.Query{OrgID: org, ActorID: "u_bob"},
			want: []string{"tool.invoke/u_bob/success", "session.create/u_bob/failure"},
		},
		{
			name: "outcome",
			q:    audit.Query{OrgID: org, Outcome: audit.Denied},
			want: []string{"connector.delete/u_ada/denied"},
		},
		{
			name: "target",
			q:    audit.Query{OrgID: org, TargetID: "c_1"},
			want: []string{"connector.delete/u_ada/denied", "connector.update/u_ada/success"},
		},
		{
			name: "filters combine",
			q:    audit.Query{OrgID: org, Category: audit.CategoryTool, ActorID: "u_ada", Outcome: audit.Success},
			want: []string{"tool.invoke/u_ada/success"},
		},
		{
			name: "a filter that matches nothing returns nothing, not everything",
			q:    audit.Query{OrgID: org, Action: "connector.create"},
			want: []string{},
		},
		{
			name: "another tenant's events stay invisible even under an exact match",
			q:    audit.Query{OrgID: "audit_t_nobody", Action: "connector.update"},
			want: []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := r.List(ctx, tc.q)
			if err != nil {
				t.Fatalf("listing %+v failed: %v", tc.q, err)
			}
			keys := []string{}
			for _, rec := range got {
				keys = append(keys, key(rec))
			}
			if strings.Join(keys, ", ") != strings.Join(tc.want, ", ") {
				t.Errorf("listing %+v returned, newest first:\n  [%s]\nwanted:\n  [%s]",
					tc.q, strings.Join(keys, ", "), strings.Join(tc.want, ", "))
			}
		})
	}

	t.Run("the caller's address survives the round trip", func(t *testing.T) {
		got, err := r.List(ctx, audit.Query{OrgID: org, Action: "session.create"})
		if err != nil {
			t.Fatalf("listing the sign-in events failed: %v", err)
		}
		byActor := map[string]string{}
		for _, rec := range got {
			byActor[rec.ActorID] = rec.IP
		}
		if byActor["u_ada"] != "203.0.113.10" {
			t.Errorf("the sign-in from 203.0.113.10 reads back with ip %q; an investigation turns on where a sign-in came from", byActor["u_ada"])
		}
		if byActor["u_bob"] != "" {
			t.Errorf("an unparseable address was stored as %q rather than dropped", byActor["u_bob"])
		}
	})

	t.Run("AfterSeq pages through the whole stream without repeats or gaps", func(t *testing.T) {
		seen := []string{}
		q := audit.Query{OrgID: org, Limit: 2}
		for page := range 10 {
			got, err := r.List(ctx, q)
			if err != nil {
				t.Fatalf("listing page %d failed: %v", page, err)
			}
			if len(got) == 0 {
				break
			}
			if len(got) > 2 {
				t.Fatalf("page %d returned %d records although Limit was 2", page, len(got))
			}
			for i, rec := range got {
				if i > 0 && got[i-1].Seq <= rec.Seq {
					t.Fatalf("page %d is not ordered newest first: seq %d precedes seq %d", page, got[i-1].Seq, rec.Seq)
				}
				seen = append(seen, key(rec))
			}
			q.AfterSeq = got[len(got)-1].Seq
		}
		if len(seen) != 6 {
			t.Fatalf("paging in twos over 6 events yielded %d records [%s]; a page boundary is dropping or repeating rows",
				len(seen), strings.Join(seen, ", "))
		}
		unique := map[string]bool{}
		for _, k := range seen {
			if unique[k] {
				t.Errorf("paging returned %s twice; AfterSeq is not advancing past the last row of the page", k)
			}
			unique[k] = true
		}
	})
}

// ---------------------------------------------------------------------------
// 7. concurrent emitters

func TestConcurrentEmittersProduceAVerifiableChain(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db)
	r := &audit.Reader{DB: db}

	// Two writers stand in for two replicas: each reads the head, hashes on
	// top of it and inserts. Without the advisory lock they would both build
	// on the same predecessor and one of the two links would be a lie.
	const writers, each = 2, 15
	g, gctx := errgroup.WithContext(ctx)
	for n := range writers {
		g.Go(func() error {
			w := audit.NewWriter(db, testLog(), audit.Options{}) //nolint:contextcheck // the writer appends from its own goroutine
			defer w.Close()
			for i := range each {
				if err := w.EmitSync(gctx, event(s.org(), "connector.update", n*each+i)); err != nil {
					return fmt.Errorf("writer %d, event %d: %w", n, i, err)
				}
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		t.Fatalf("concurrent appends failed: %v", err)
	}

	lo, hi := s.bounds(ctx)
	res, err := r.Verify(ctx, lo, hi)
	if err != nil {
		t.Fatalf("Verify over seq %d..%d failed before it could reach a verdict: %v", lo, hi, err)
	}
	if !res.Valid {
		t.Fatalf("%d events appended by %d writers at once leave the chain broken at seq %d (%q); the advisory lock is not serialising appends",
			writers*each, writers, res.BrokenAt, res.Explained)
	}
	if res.Checked != writers*each {
		t.Errorf("Verify walked %d rows over seq %d..%d, but %d events were appended", res.Checked, lo, hi, writers*each)
	}

	// Two appends that raced on the same predecessor would produce two rows
	// claiming the same prev_hash, which the walk above would miss if the
	// loser were the last row of the range.
	var rows, distinct int
	if err := db.Bypass(ctx, "audit test duplicates", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*), count(DISTINCT prev_hash) FROM audit_events WHERE organization_id = $1`, s.org()).Scan(&rows, &distinct)
	}); err != nil {
		t.Fatalf("could not count the appended rows: %v", err)
	}
	if rows != distinct {
		t.Errorf("%d rows share only %d distinct predecessors; two appends built on the same head", rows, distinct)
	}
}

// ---------------------------------------------------------------------------
// the append path

func TestAnOversizedPayloadIsTruncatedNotRefused(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db)
	w := audit.NewWriter(db, testLog(), audit.Options{MaxPayloadBytes: 256})
	defer w.Close()

	// A tool that returns a megabyte must not be able to suppress its own
	// audit record: losing the payload is a smaller loss than losing the
	// fact that the call happened.
	e := event(s.org(), "tool.invoke", 0)
	e.Payload = map[string]any{"output": strings.Repeat("x", 4096)}
	emitSync(ctx, t, w, e)

	got, err := (&audit.Reader{DB: db}).List(ctx, audit.Query{OrgID: s.org()})
	if err != nil {
		t.Fatalf("listing the event back failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("a %d-byte payload cost the whole event: %d records came back, wanted 1", 4096, len(got))
	}
	stored, _ := got[0].Payload.(map[string]any)
	if stored["_truncated"] != true {
		t.Errorf("a payload over the 256-byte cap reads back as %#v; it should be replaced by a marker saying it was truncated", got[0].Payload)
	}
	if strings.Contains(fmt.Sprint(got[0].Payload), strings.Repeat("x", 300)) {
		t.Errorf("the payload was stored in full despite the 256-byte cap")
	}

	lo, hi := s.bounds(ctx)
	res, err := (&audit.Reader{DB: db}).Verify(ctx, lo, hi)
	if err != nil {
		t.Fatalf("Verify over seq %d..%d failed: %v", lo, hi, err)
	}
	if !res.Valid {
		t.Errorf("an event whose payload was truncated at write time verifies as broken at seq %d (%q); the digest has to cover what was stored",
			res.BrokenAt, res.Explained)
	}
}

func TestFromPrincipalFillsTheActor(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   audit.Event
		p    *authz.Principal
		want audit.Event
	}{
		{
			// An unauthenticated request still produces events, and they must
			// not silently look like they came from somebody.
			name: "no principal is anonymous",
			in:   audit.Event{Action: "session.create"},
			want: audit.Event{Action: "session.create", ActorKind: "anonymous"},
		},
		{
			name: "a signed-in user",
			in:   audit.Event{Action: "connector.update"},
			p:    &authz.Principal{Kind: authz.KindUser, ID: "u_ada", OrgID: "org_1", SessionID: "s_1", Email: "ada@example.com"},
			want: audit.Event{Action: "connector.update", ActorKind: "user", ActorID: "u_ada", ActorDisplay: "ada@example.com",
				SessionID: "s_1", OrgID: "org_1"},
		},
		{
			// An event that already names an organisation is talking about
			// that one; the principal's must not overwrite it.
			name: "an explicit organisation wins over the principal's",
			in:   audit.Event{Action: "member.remove", OrgID: "org_other"},
			p:    &authz.Principal{Kind: authz.KindServiceAccount, ID: "sa_1", OrgID: "org_1"},
			want: audit.Event{Action: "member.remove", OrgID: "org_other", ActorKind: "service_account", ActorID: "sa_1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := audit.FromPrincipal(tc.in, tc.p)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("FromPrincipal produced:\n  %+v\nwanted:\n  %+v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// the nil sink

func TestNilWriterDiscardsWithoutPanicking(t *testing.T) {
	t.Parallel()

	// Half the call sites hold a *Writer that may never have been built, and
	// none of them check. A nil one has to behave like a sink that forgets.
	ctx := context.Background()
	var w *audit.Writer
	var sink audit.Sink = w
	sink.Emit(ctx, audit.Event{Category: audit.CategoryAdmin, Action: "connector.update"})
	if err := w.EmitSync(ctx, audit.Event{Action: "connector.update"}); err != nil {
		t.Errorf("EmitSync on a nil *Writer returned %v; it should discard the event and report success", err)
	}
	if err := w.Flush(ctx); err != nil {
		t.Errorf("Flush on a nil *Writer returned %v; there is nothing queued to fail", err)
	}
}

// TestVerifyChecksCheckpoints covers what the links alone cannot catch:
// a chain rewritten from some row onward with every later hash
// recomputed, and rows deleted from the head. Either leaves a signed
// checkpoint that no longer matches the rows it vouched for.
func TestVerifyChecksCheckpoints(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)

	// A stand-in for the keyring: the signature is a keyed digest of the
	// hash, which is enough to tell a genuine checkpoint from an edited
	// one. The keyring's own ECDSA check is tested in mcpauth.
	sign := func(b []byte) (string, error) {
		d := sha256.Sum256(append([]byte("anchor-key"), b...))
		return "test:" + hex.EncodeToString(d[:]), nil
	}
	verify := func(_ context.Context, b []byte, sig string) error {
		want, _ := sign(b)
		if sig != want {
			return errors.New("signature does not verify")
		}
		return nil
	}
	r := &audit.Reader{DB: db, VerifyAnchor: verify}

	setup := func(t *testing.T) (*stream, int64, int64) {
		t.Helper()
		s := newStream(ctx, t, db)
		w := audit.NewWriter(db, testLog(), audit.Options{}) //nolint:contextcheck // the writer appends from its own goroutine
		defer w.Close()
		for i := range 4 {
			emitSync(ctx, t, w, event(s.org(), "connector.update", i))
		}
		if err := r.Anchor(ctx, sign); err != nil {
			t.Fatalf("anchoring failed: %v", err)
		}
		lo, hi := s.bounds(ctx)
		return s, lo, hi
	}

	t.Run("an intact chain matches its checkpoint", func(t *testing.T) {
		_, lo, hi := setup(t)
		res, err := r.Verify(ctx, lo, hi)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Valid || res.Anchors != 1 {
			t.Fatalf("got valid=%v anchors=%d (%s), want a valid chain with its one checkpoint matched", res.Valid, res.Anchors, res.Explained)
		}
	})

	t.Run("a rewritten row no longer matches its checkpoint", func(t *testing.T) {
		_, lo, hi := setup(t)
		// Rewriting the chain and recomputing every hash after the edit
		// leaves the head hashing to something new. Moving the checkpoint
		// instead is the same disagreement seen from the other side.
		maintExec(ctx, t, db, `UPDATE audit_anchors SET hash = sha256(hash) WHERE seq = $1`, hi)
		res, err := r.Verify(ctx, lo, hi)
		if err != nil {
			t.Fatal(err)
		}
		if res.Valid || res.BrokenAt != hi || !strings.Contains(res.Explained, "checkpoint recorded") {
			t.Fatalf("got valid=%v brokenAt=%d (%s), want a break at the checkpoint on row %d", res.Valid, res.BrokenAt, res.Explained, hi)
		}
	})

	t.Run("a checkpoint edited to match is not validly signed", func(t *testing.T) {
		_, lo, hi := setup(t)
		maintExec(ctx, t, db, `UPDATE audit_anchors SET signature = 'test:00' WHERE seq = $1`, hi)
		res, err := r.Verify(ctx, lo, hi)
		if err != nil {
			t.Fatal(err)
		}
		if res.Valid || !strings.Contains(res.Explained, "not validly signed") {
			t.Fatalf("got valid=%v (%s), want the forged signature refused", res.Valid, res.Explained)
		}
	})

	t.Run("an unsigned checkpoint is counted, not trusted", func(t *testing.T) {
		_, lo, hi := setup(t)
		maintExec(ctx, t, db, `UPDATE audit_anchors SET signature = NULL WHERE seq = $1`, hi)
		res, err := r.Verify(ctx, lo, hi)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Valid || res.Unsigned != 1 {
			t.Fatalf("got valid=%v unsigned=%d (%s), want a valid chain reporting one unsigned checkpoint", res.Valid, res.Unsigned, res.Explained)
		}
	})

	t.Run("rows deleted from the head leave a checkpoint past the end", func(t *testing.T) {
		_, lo, hi := setup(t)
		maintExec(ctx, t, db, `DELETE FROM audit_events WHERE seq = $1`, hi)
		res, err := r.Verify(ctx, lo, hi)
		if err != nil {
			t.Fatal(err)
		}
		if res.Valid || !strings.Contains(res.Explained, "removed from the head") {
			t.Fatalf("got valid=%v (%s), want the missing head reported", res.Valid, res.Explained)
		}
	})
}
