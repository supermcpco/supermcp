package audit

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func entries(n int, action string) []spoolEntry {
	out := make([]spoolEntry, n)
	for i := range out {
		out[i] = spoolEntry{
			At: time.Date(2026, 3, 4, 5, 6, i, 0, time.UTC),
			Event: Event{OrgID: "org_1", Category: CategoryAdmin, Action: action, Outcome: Success,
				ActorKind: "user", ActorID: "u_1", Meta: map[string]any{"n": i}},
		}
	}
	return out
}

func TestSpoolKeepsOrderAcrossSegments(t *testing.T) {
	t.Parallel()
	s, err := OpenSpool(t.TempDir(), 1<<20, quietLog())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Write(entries(2, "first")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.Write(entries(3, "second")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if s.Depth() != 5 {
		t.Fatalf("depth = %d, want 5", s.Depth())
	}
	if s.Empty() {
		t.Fatal("a spool holding five events is not empty")
	}

	for _, want := range []struct {
		action string
		count  int
	}{{"first", 2}, {"second", 3}} {
		seg, ok, err := s.Oldest()
		if err != nil || !ok {
			t.Fatalf("oldest: %v (found %v)", err, ok)
		}
		if len(seg.Entries) != want.count || seg.Entries[0].Event.Action != want.action {
			t.Fatalf("segment = %d entries of %q, want %d of %q",
				len(seg.Entries), seg.Entries[0].Event.Action, want.count, want.action)
		}
		if err := s.Remove(seg.Name); err != nil {
			t.Fatalf("remove: %v", err)
		}
	}
	if !s.Empty() || s.Depth() != 0 || s.Bytes() != 0 {
		t.Fatalf("after replaying everything: empty=%v depth=%d bytes=%d", s.Empty(), s.Depth(), s.Bytes())
	}
	_, ok, err := s.Oldest()
	if err != nil || ok {
		t.Fatalf("an empty spool returned a segment: %v %v", ok, err)
	}
}

// A restart has to pick up what the last process left, in the order it
// left it, or the spool has only moved the loss rather than prevented it.
func TestSpoolSurvivesAReopen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first, err := OpenSpool(dir, 1<<20, quietLog())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := first.Write(entries(2, "before")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A segment that never finished being written is rubbish, not data.
	if err := os.WriteFile(filepath.Join(dir, "00000000000000000009-000001.ndjson.tmp"), []byte("{"), 0o600); err != nil {
		t.Fatalf("stage a torn segment: %v", err)
	}

	second, err := OpenSpool(dir, 1<<20, quietLog())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if second.Depth() != 2 {
		t.Fatalf("depth after a reopen = %d, want the two events that were waiting", second.Depth())
	}
	if err := second.Write(entries(1, "after")); err != nil {
		t.Fatalf("write after the reopen: %v", err)
	}
	seg, ok, err := second.Oldest()
	if err != nil || !ok {
		t.Fatalf("oldest: %v %v", err, ok)
	}
	if seg.Entries[0].Event.Action != "before" {
		t.Fatalf("oldest segment holds %q, want the events from the earlier run first", seg.Entries[0].Event.Action)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(left) != 0 {
		t.Fatalf("a torn segment was kept: %v", left)
	}
}

// The bound is what stops the spool taking the disk, and the gateway with
// it. Past it a write is refused so the caller can count the loss.
func TestSpoolIsBounded(t *testing.T) {
	t.Parallel()
	s, err := OpenSpool(t.TempDir(), 512, quietLog())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Write(entries(1, "small")); err != nil {
		t.Fatalf("the first write should fit: %v", err)
	}
	err = s.Write(entries(20, "too-much"))
	if err == nil {
		t.Fatal("a spool past its bound must refuse rather than grow")
	}
	if !strings.Contains(err.Error(), ErrSpoolFull.Error()) {
		t.Fatalf("error = %v, want it to say the spool is full", err)
	}
	if s.Depth() != 1 {
		t.Fatalf("depth = %d, want the refused batch not to have been counted", s.Depth())
	}
}

// A line that will not decode loses that event and no other: the events
// around a torn tail are still evidence.
func TestSpoolReadsPastADamagedLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := OpenSpool(dir, 1<<20, quietLog())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Write(entries(2, "kept")); err != nil {
		t.Fatalf("write: %v", err)
	}
	names, _ := filepath.Glob(filepath.Join(dir, "*.ndjson"))
	if len(names) != 1 {
		t.Fatalf("segments = %v", names)
	}
	body, err := os.ReadFile(names[0])
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := os.WriteFile(names[0], append(body, []byte("{\"at\":\"2026\n")...), 0o600); err != nil {
		t.Fatalf("append a torn line: %v", err)
	}
	seg, ok, err := s.Oldest()
	if err != nil || !ok {
		t.Fatalf("oldest: %v %v", err, ok)
	}
	if len(seg.Entries) != 2 {
		t.Fatalf("entries = %d, want the two whole ones", len(seg.Entries))
	}
}

func TestSpoolNeedsADirectory(t *testing.T) {
	t.Parallel()
	if _, err := OpenSpool("", 0, quietLog()); err == nil {
		t.Fatal("a spool without a directory must be refused, not silently disabled")
	}
}

func TestSpooledMetaKeepsTheOriginalTime(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	meta := spooledMeta(map[string]any{"requestId": "req_1"}, at)
	if meta["requestId"] != "req_1" {
		t.Fatalf("meta = %v, want what the event already carried", meta)
	}
	if meta["spooled"] != true {
		t.Fatalf("meta = %v, want the record to say it waited on disk", meta)
	}
	if meta["occurredAt"] != at.Format(time.RFC3339Nano) {
		t.Fatalf("occurredAt = %v, want when the event happened", meta["occurredAt"])
	}
	// The original map must not be the one that was changed: the caller
	// may still be holding it, and an event's content is evidence.
	original := map[string]any{"a": 1}
	_ = spooledMeta(original, at)
	if len(original) != 1 {
		t.Fatalf("the event's own meta was modified: %v", original)
	}
}

// An event that arrives when the queue is full is parked rather than
// dropped, and the park is bounded: a database that is away must not turn
// into memory that grows until the process dies.
func TestParkingIsBounded(t *testing.T) {
	t.Parallel()
	w := &Writer{opts: Options{Buffer: 2}, spool: &Spool{}}
	for i := range 2 {
		if !w.park(&pending{event: &Event{Action: "parked"}, at: time.Now()}) {
			t.Fatalf("event %d was refused while the park had room", i)
		}
	}
	if w.park(&pending{event: &Event{Action: "one too many"}}) {
		t.Fatal("the park took an event past its bound")
	}
	taken := w.takeOverflow()
	if len(taken) != 2 {
		t.Fatalf("took %d parked events, want 2", len(taken))
	}
	if w.takeOverflow() != nil {
		t.Fatal("the park handed the same events over twice")
	}

	// Without a spool there is nothing to park into, so the caller falls
	// through to counting the loss.
	none := &Writer{opts: Options{Buffer: 2}}
	if none.park(&pending{event: &Event{}}) {
		t.Fatal("a writer with no spool parked an event it cannot write anywhere")
	}
}

func TestOptionsFromEnv(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"SUPERMCP_AUDIT_ON_UNAVAILABLE":  "spool",
		"SUPERMCP_AUDIT_SPOOL_DIR":       "/var/spool/audit",
		"SUPERMCP_AUDIT_SPOOL_MAX_BYTES": "1048576",
	}
	o := OptionsFromEnv(func(k string) string { return env[k] })
	if o.OnUnavailable != UnavailableSpool || o.SpoolDir != "/var/spool/audit" || o.SpoolMaxBytes != 1<<20 {
		t.Fatalf("options = %+v", o)
	}
	empty := OptionsFromEnv(func(string) string { return "" })
	if empty.OnUnavailable != "" || empty.SpoolMaxBytes != 0 {
		t.Fatalf("an unset environment must leave the defaults to the writer: %+v", empty)
	}
}
