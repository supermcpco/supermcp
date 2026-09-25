package audit_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// audit_events is partitioned by month on ts (migration 00033). These tests
// give each aged stream a year nobody else writes to, so a partition they
// create, fill, cut or drop holds only their own events.

// at is a writer clock stopped at one instant: the timestamp is hashed, so
// an aged event is written with an aged clock rather than edited later.
func at(ts time.Time) audit.Options {
	return audit.Options{Now: func() time.Time { return ts }}
}

func date(y int, m time.Month, d, h, mi, s int) time.Time {
	return time.Date(y, m, d, h, mi, s, 0, time.UTC)
}

// monthsFor creates the partitions for the months from..through and drops
// them again when the test ends. Register it before newStream, so the
// stream's own cleanup has emptied them by then.
func monthsFor(ctx context.Context, t *testing.T, db *tenant.DB, from, through time.Time) []string {
	t.Helper()
	parts := &audit.Partitions{DB: db}
	var names []string
	for m := from; !m.After(through); m = m.AddDate(0, 1, 0) {
		names = append(names, "audit_events_p"+m.Format("200601"))
	}
	dropPartitions(ctx, t, db, names...)
	if _, err := parts.Ensure(ctx, from, through); err != nil {
		t.Fatalf("creating the partitions %v failed: %v", names, err)
	}
	t.Cleanup(func() { dropPartitions(context.WithoutCancel(ctx), t, db, names...) })
	return names
}

// dropPartitions detaches and drops the named partitions where they exist.
func dropPartitions(ctx context.Context, t *testing.T, db *tenant.DB, names ...string) {
	t.Helper()
	err := db.Bypass(ctx, "audit test drop partitions", func(tx pgx.Tx) error {
		for _, name := range names {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT to_regclass('public.' || quote_ident($1)) IS NOT NULL`, name).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				continue
			}
			ident := pgx.Identifier{name}.Sanitize()
			if _, err := tx.Exec(ctx, `ALTER TABLE audit_events DETACH PARTITION `+ident); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DROP TABLE `+ident); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("could not drop the partitions %v: %v", names, err)
	}
}

func partitionExists(ctx context.Context, t *testing.T, db *tenant.DB, name string) bool {
	t.Helper()
	var exists bool
	err := db.Bypass(ctx, "audit test partition exists", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT to_regclass('public.' || quote_ident($1)) IS NOT NULL`, name).Scan(&exists)
	})
	if err != nil {
		t.Fatalf("could not look up partition %s: %v", name, err)
	}
	return exists
}

// partitionOfSeq names the partition a row is stored in.
func partitionOfSeq(ctx context.Context, t *testing.T, db *tenant.DB, seq int64) string {
	t.Helper()
	var name string
	err := db.Bypass(ctx, "audit test partition of", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tableoid::regclass::text FROM audit_events WHERE seq = $1`, seq).Scan(&name)
	})
	if err != nil {
		t.Fatalf("could not find which partition holds seq %d: %v", seq, err)
	}
	return name
}

func writeAt(ctx context.Context, t *testing.T, db *tenant.DB, ts time.Time, org string, n int) {
	t.Helper()
	w := audit.NewWriter(db, testLog(), at(ts)) //nolint:contextcheck // the writer appends from its own goroutine
	defer w.Close()
	for i := range n {
		emitSync(ctx, t, w, event(org, "connector.update", i))
	}
}

func TestAnInsertLandsInItsMonthsPartition(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	may := monthsFor(ctx, t, db, date(2003, 5, 1, 0, 0, 0), date(2003, 5, 1, 0, 0, 0))
	t.Cleanup(func() { dropPartitions(context.WithoutCancel(ctx), t, db, "audit_events_p200307") })
	s := newStream(ctx, t, db)

	writeAt(ctx, t, db, date(2003, 5, 15, 12, 0, 0), s.org(), 1)
	// July has no partition yet. The event is kept, not refused: refusing
	// it would refuse the audit event.
	writeAt(ctx, t, db, date(2003, 7, 4, 12, 0, 0), s.org(), 1)
	seqs := s.seqs(ctx)
	if len(seqs) != 2 {
		t.Fatalf("wrote 2 events and found %d", len(seqs))
	}
	if got := partitionOfSeq(ctx, t, db, seqs[0]); got != may[0] {
		t.Errorf("an event written on 15 May 2003 is stored in %s, want %s", got, may[0])
	}
	if got := partitionOfSeq(ctx, t, db, seqs[1]); got != "audit_events_default" {
		t.Errorf("an event for a month with no partition is stored in %s, want audit_events_default", got)
	}

	// Creating the month moves what the default partition holds for it.
	parts := &audit.Partitions{DB: db}
	if n, err := parts.Ensure(ctx, date(2003, 7, 1, 0, 0, 0), date(2003, 7, 1, 0, 0, 0)); err != nil || n != 1 {
		t.Fatalf("creating July 2003 created %d partitions (err %v), want 1", n, err)
	}
	if got := partitionOfSeq(ctx, t, db, seqs[1]); got != "audit_events_p200307" {
		t.Errorf("after July 2003 was created, its event is stored in %s, want audit_events_p200307", got)
	}
	lo, hi := s.bounds(ctx)
	res, err := (&audit.Reader{DB: db}).Verify(ctx, lo, hi)
	if err != nil || !res.Valid || res.Checked != 2 {
		t.Errorf("moving an event out of the default partition broke the chain: %+v, %v", res, err)
	}
}

func TestMaintainCreatesTheMonthsAhead(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	want := []string{"audit_events_p209001", "audit_events_p209002", "audit_events_p209003", "audit_events_p209004"}
	dropPartitions(ctx, t, db, append(want, "audit_events_p209005")...)
	t.Cleanup(func() { dropPartitions(context.WithoutCancel(ctx), t, db, append(want, "audit_events_p209005")...) })

	// The last day of a month is where adding three months overshoots:
	// 31 January plus three months is 1 May.
	parts := &audit.Partitions{DB: db, Now: func() time.Time { return date(2090, 1, 31, 22, 0, 0) }}
	created, err := parts.Maintain(ctx)
	if err != nil {
		t.Fatalf("the maintenance run failed: %v", err)
	}
	if created != 4 {
		t.Errorf("the first run created %d partitions, want the current month and the %d after it", created, audit.PartitionsAhead)
	}
	for _, name := range want {
		if !partitionExists(ctx, t, db, name) {
			t.Errorf("%s was not created", name)
		}
	}
	if partitionExists(ctx, t, db, "audit_events_p209005") {
		t.Errorf("audit_events_p209005 was created; that is %d months ahead, one too many", audit.PartitionsAhead+1)
	}
	if again, err := parts.Maintain(ctx); err != nil || again != 0 {
		t.Errorf("a second run created %d partitions (err %v); it should find nothing to do", again, err)
	}
	if ahead, err := parts.MonthsAhead(ctx); err != nil || ahead != audit.PartitionsAhead {
		t.Errorf("months ahead after maintenance = %d (err %v), want %d", ahead, err, audit.PartitionsAhead)
	}

	// A partition is reached through audit_events and its policy only:
	// the application role has nothing on it, whatever the default
	// privileges would have given a new table.
	err = db.Bypass(ctx, "audit test partition privileges", func(tx pgx.Tx) error {
		var readable, writable, rls bool
		if err := tx.QueryRow(ctx, `SELECT has_table_privilege('supermcp_app', $1, 'SELECT'),
				has_table_privilege('supermcp_app', $1, 'INSERT,UPDATE,DELETE,TRUNCATE'),
				(SELECT relrowsecurity FROM pg_class WHERE oid = $1::regclass)`, want[0]).Scan(&readable, &writable, &rls); err != nil {
			return err
		}
		if readable || writable || !rls {
			t.Errorf("%s: the application role can read it %v, write it %v; row-level security on %v", want[0], readable, writable, rls)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMonthsAheadCountsContiguousMonths(t *testing.T) {
	t.Parallel()
	month := func(y int, m time.Month) audit.PartitionBound {
		from := date(y, m, 1, 0, 0, 0)
		return audit.PartitionBound{Name: "audit_events_p" + from.Format("200601"), From: from, To: from.AddDate(0, 1, 0)}
	}
	now := date(2026, 9, 26, 10, 0, 0)
	tests := []struct {
		name   string
		bounds []audit.PartitionBound
		want   int
	}{
		{name: "no partitions", want: -1},
		{name: "only past months", bounds: []audit.PartitionBound{month(2026, 7), month(2026, 8)}, want: -1},
		{name: "the current month only", bounds: []audit.PartitionBound{month(2026, 8), month(2026, 9)}, want: 0},
		{name: "three ahead", bounds: []audit.PartitionBound{month(2026, 9), month(2026, 10), month(2026, 11), month(2026, 12)}, want: 3},
		{name: "a gap stops the count", bounds: []audit.PartitionBound{month(2026, 9), month(2026, 10), month(2026, 12)}, want: 1},
		{name: "the current month missing", bounds: []audit.PartitionBound{month(2026, 10), month(2026, 11)}, want: -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := audit.MonthsAheadOf(now, tc.bounds); got != tc.want {
				t.Errorf("months ahead = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestVerifyAcrossAPartitionBoundary(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	names := monthsFor(ctx, t, db, date(2002, 3, 1, 0, 0, 0), date(2002, 4, 1, 0, 0, 0))
	s := newStream(ctx, t, db)

	writeAt(ctx, t, db, date(2002, 3, 31, 23, 59, 59), s.org(), 3)
	writeAt(ctx, t, db, date(2002, 4, 1, 0, 0, 1), s.org(), 3)
	seqs := s.seqs(ctx)
	if got := []string{partitionOfSeq(ctx, t, db, seqs[2]), partitionOfSeq(ctx, t, db, seqs[3])}; !slices.Equal(got, names) {
		t.Fatalf("the last March and first April events are stored in %v, want %v", got, names)
	}
	lo, hi := s.bounds(ctx)
	res, err := (&audit.Reader{DB: db}).Verify(ctx, lo, hi)
	if err != nil {
		t.Fatalf("Verify over seq %d..%d failed before it could reach a verdict: %v", lo, hi, err)
	}
	if !res.Valid || res.Checked != 6 {
		t.Errorf("a chain running from one month's partition into the next does not verify: %+v", res)
	}
}

func TestRetentionDropsAWholeMonth(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	names := monthsFor(ctx, t, db, date(2001, 1, 1, 0, 0, 0), date(2001, 2, 1, 0, 0, 0))
	s := newStream(ctx, t, db)

	writeAt(ctx, t, db, date(2001, 1, 10, 9, 0, 0), s.org(), 3)
	writeAt(ctx, t, db, date(2001, 2, 10, 9, 0, 0), s.org(), 2)
	writeAt(ctx, t, db, date(2001, 2, 20, 9, 0, 0), s.org(), 2)
	seqs := s.seqs(ctx)
	lo, hi := s.bounds(ctx)

	// January ended before the cutoff and holds nothing above the cut, so
	// it goes as a partition; February straddles the cutoff and loses its
	// rows below the cut one by one.
	r := &audit.Reader{DB: db}
	cut, err := r.Cut(ctx, date(2001, 2, 15, 0, 0, 0))
	if err != nil {
		t.Fatalf("cutting at 15 February 2001 failed: %v", err)
	}
	if !slices.Equal(cut.Partitions, names[:1]) {
		t.Errorf("the cut dropped the partitions %v, want %v", cut.Partitions, names[:1])
	}
	if cut.Seq != seqs[4] {
		t.Errorf("the cut is at seq %d, want %d, the last event before 15 February", cut.Seq, seqs[4])
	}
	if cut.Deleted < 5 {
		t.Errorf("the cut removed %d events; the 3 in January and 2 before 15 February were due", cut.Deleted)
	}
	if partitionExists(ctx, t, db, names[0]) {
		t.Errorf("%s is still there after the cut", names[0])
	}
	if !partitionExists(ctx, t, db, names[1]) {
		t.Errorf("%s was dropped, but it holds events newer than the cut", names[1])
	}
	if survivors := s.seqs(ctx); !slices.Equal(survivors, seqs[5:]) {
		t.Errorf("after the cut the surviving sequences are %v, want %v", survivors, seqs[5:])
	}

	// A dropped month is the same cut as deleted rows, bridged by the same
	// anchor.
	res, err := r.Verify(ctx, lo, hi)
	if err != nil {
		t.Fatalf("Verify over seq %d..%d failed before it could reach a verdict: %v", lo, hi, err)
	}
	if !res.Valid {
		t.Fatalf("after retention dropped %s, Verify reports the chain broken at seq %d (%q)", names[0], res.BrokenAt, res.Explained)
	}
	if res.RetentionCut != cut.Seq || res.FirstSeq != seqs[5] || res.Checked != 2 {
		t.Errorf("Verify started at seq %d after the retention cut at %d and walked %d rows; want seq %d after %d, 2 rows",
			res.FirstSeq, res.RetentionCut, res.Checked, seqs[5], cut.Seq)
	}
}

func TestCutKeepsAMonthWithALegalHold(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	names := monthsFor(ctx, t, db, date(2004, 1, 1, 0, 0, 0), date(2004, 1, 1, 0, 0, 0))
	s := newStream(ctx, t, db)

	writeAt(ctx, t, db, date(2004, 1, 10, 9, 0, 0), s.org(), 3)
	seqs := s.seqs(ctx)
	lo, hi := s.bounds(ctx)
	maintExec(ctx, t, db, `UPDATE audit_events SET legal_hold = true WHERE seq = $1`, seqs[1])

	r := &audit.Reader{DB: db}
	cut, err := r.Cut(ctx, date(2004, 3, 1, 0, 0, 0))
	if err != nil {
		t.Fatalf("cutting a month with a row under legal hold failed: %v", err)
	}
	if len(cut.Partitions) != 0 || !partitionExists(ctx, t, db, names[0]) {
		t.Fatalf("the cut dropped %v; %s holds a row under legal hold and must stay", cut.Partitions, names[0])
	}
	if survivors := s.seqs(ctx); !slices.Equal(survivors, seqs[1:]) {
		t.Errorf("after the cut the surviving sequences are %v; the held row and the one after it should be left", survivors)
	}
	if res, err := r.Verify(ctx, lo, hi); err != nil || !res.Valid {
		t.Errorf("the chain does not verify after a cut stopped by a legal hold: %+v, %v", res, err)
	}
}

// TestCutGivesUpWhenTheTableIsBusy holds audit_events open in another
// transaction, as a long export or verify would, while a cut has a month to
// drop. The cut must not wait for ever, with every append queued behind
// it, and must not leave half a cut behind.
func TestCutGivesUpWhenTheTableIsBusy(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	names := monthsFor(ctx, t, db, date(2006, 1, 1, 0, 0, 0), date(2006, 1, 1, 0, 0, 0))
	s := newStream(ctx, t, db)
	writeAt(ctx, t, db, date(2006, 1, 10, 9, 0, 0), s.org(), 3)
	seqs := s.seqs(ctx)

	reader, err := db.Maint.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := reader.Exec(ctx, `SELECT count(*) FROM audit_events WHERE seq = $1`, seqs[0]); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	_, err = (&audit.Reader{DB: db}).Cut(ctx, date(2006, 3, 1, 0, 0, 0))
	if err == nil {
		t.Fatalf("the cut dropped %s while another transaction was reading audit_events", names[0])
	}
	if !strings.Contains(err.Error(), "busy") {
		t.Errorf("the cut failed with %v; it should say the table was busy", err)
	}
	if waited := time.Since(started); waited > 30*time.Second {
		t.Errorf("the cut waited %s for the table", waited)
	}
	if err := reader.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if !partitionExists(ctx, t, db, names[0]) || len(s.seqs(ctx)) != 3 {
		t.Errorf("a cut that gave up left %s changed: partition there %v, %d of 3 rows",
			names[0], partitionExists(ctx, t, db, names[0]), len(s.seqs(ctx)))
	}
	var anchored bool
	err = db.Bypass(ctx, "audit test anchor", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT true FROM audit_anchors WHERE seq = $1`, seqs[2]).Scan(&anchored)
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("a cut that gave up left an anchor at seq %d (%v)", seqs[2], err)
	}
}

func TestVerifyCatchesADroppedPartition(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	names := monthsFor(ctx, t, db, date(2005, 1, 1, 0, 0, 0), date(2005, 3, 1, 0, 0, 0))
	s := newStream(ctx, t, db)

	writeAt(ctx, t, db, date(2005, 1, 10, 9, 0, 0), s.org(), 2)
	writeAt(ctx, t, db, date(2005, 2, 10, 9, 0, 0), s.org(), 2)
	writeAt(ctx, t, db, date(2005, 3, 10, 9, 0, 0), s.org(), 2)
	seqs := s.seqs(ctx)
	lo, hi := s.bounds(ctx)

	// Dropping a month by hand, not through retention, is a deletion like
	// any other: no anchor explains it.
	dropPartitions(ctx, t, db, names[1])
	res, err := (&audit.Reader{DB: db}).Verify(ctx, lo, hi)
	if err != nil {
		t.Fatalf("Verify over seq %d..%d failed before it could reach a verdict: %v", lo, hi, err)
	}
	if res.Valid {
		t.Fatalf("February 2005 was dropped from the middle of the chain and Verify still reports it intact")
	}
	if res.BrokenAt != seqs[4] {
		t.Errorf("Verify blames seq %d; seq %d is the first row whose predecessor went with the partition", res.BrokenAt, seqs[4])
	}
	if !strings.Contains(res.Explained, strconv.FormatInt(seqs[4], 10)) || !strings.Contains(res.Explained, "removed") {
		t.Errorf("the verdict %q does not say which row lost its predecessor and that rows were removed", res.Explained)
	}
}
