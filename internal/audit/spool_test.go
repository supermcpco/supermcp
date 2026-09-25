package audit

import (
	"errors"
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
	s, err := OpenSpool(SpoolConfig{Dir: t.TempDir(), Instance: "r1", MaxBytes: 1 << 20}, quietLog())
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
	first, err := OpenSpool(SpoolConfig{Dir: dir, Instance: "r1", MaxBytes: 1 << 20}, quietLog())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := first.Write(entries(2, "before")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A segment that never finished being written is rubbish, not data.
	if err := os.WriteFile(filepath.Join(dir, "r1", "00000000000000000009-000001-r1.ndjson.tmp"), []byte("{"), 0o600); err != nil {
		t.Fatalf("stage a torn segment: %v", err)
	}

	second, err := OpenSpool(SpoolConfig{Dir: dir, Instance: "r1", MaxBytes: 1 << 20}, quietLog())
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
	if left, _ := filepath.Glob(filepath.Join(dir, "r1", "*.tmp")); len(left) != 0 {
		t.Fatalf("a torn segment was kept: %v", left)
	}
}

// The bound is what stops the spool taking the disk, and the gateway with
// it. Past it a write is refused so the caller can count the loss.
func TestSpoolIsBounded(t *testing.T) {
	t.Parallel()
	s, err := OpenSpool(SpoolConfig{Dir: t.TempDir(), Instance: "r1", MaxBytes: 512}, quietLog())
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
	s, err := OpenSpool(SpoolConfig{Dir: dir, Instance: "r1", MaxBytes: 1 << 20}, quietLog())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Write(entries(2, "kept")); err != nil {
		t.Fatalf("write: %v", err)
	}
	names, _ := filepath.Glob(filepath.Join(dir, "r1", "*.ndjson"))
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
	if _, err := OpenSpool(SpoolConfig{Instance: "r1"}, quietLog()); err == nil {
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
		"SUPERMCP_AUDIT_ON_UNAVAILABLE":   "spool",
		"SUPERMCP_AUDIT_SPOOL_DIR":        "/var/spool/audit",
		"SUPERMCP_AUDIT_SPOOL_MAX_BYTES":  "1048576",
		"SUPERMCP_AUDIT_SPOOL_ORPHAN_AGE": "5m",
		"SUPERMCP_INSTANCE_ID":            "pod-a",
	}
	o := OptionsFromEnv(func(k string) string { return env[k] })
	if o.OnUnavailable != UnavailableSpool || o.SpoolDir != "/var/spool/audit" || o.SpoolMaxBytes != 1<<20 ||
		o.SpoolOrphanAge != 5*time.Minute || o.Instance != "pod-a" {
		t.Fatalf("options = %+v", o)
	}
	empty := OptionsFromEnv(func(string) string { return "" })
	if empty.OnUnavailable != "" || empty.SpoolMaxBytes != 0 {
		t.Fatalf("an unset environment must leave the defaults to the writer: %+v", empty)
	}
}

// ageHeartbeat makes a replica's directory look abandoned.
func ageHeartbeat(t *testing.T, root, instance string, age time.Duration) {
	t.Helper()
	old := time.Now().Add(-age)
	if err := os.Chtimes(filepath.Join(root, instance, spoolHeartbeat), old, old); err != nil {
		t.Fatalf("age %s's heartbeat: %v", instance, err)
	}
}

// A replica whose heartbeat is fresh keeps its segments: another replica
// on the same volume neither reads them nor counts them.
func TestSpoolLeavesALiveReplicaAlone(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	a, err := OpenSpool(SpoolConfig{Dir: root, Instance: "pod-a"}, quietLog())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := a.Write(entries(3, "a")); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := OpenSpool(SpoolConfig{Dir: root, Instance: "pod-b"}, quietLog())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if b.Depth() != 0 || a.Depth() != 3 {
		t.Fatalf("depths a=%d b=%d, want a=3 b=0: a live replica's segments are its own", a.Depth(), b.Depth())
	}
}

// Two replicas racing for one abandoned directory: exactly one takes it,
// and once it has replayed everything the adopted directory is gone.
func TestSpoolAdoptsAnAbandonedReplicaOnce(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	gone, err := OpenSpool(SpoolConfig{Dir: root, Instance: "pod-gone"}, quietLog())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for range 3 {
		if err := gone.Write(entries(2, "gone")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	ageHeartbeat(t, root, "pod-gone", time.Hour)

	spools := make([]*Spool, 2)
	errs := make([]error, 2)
	done := make(chan struct{})
	for i, name := range []string{"pod-c", "pod-d"} {
		go func() {
			defer func() { done <- struct{}{} }()
			spools[i], errs[i] = OpenSpool(SpoolConfig{Dir: root, Instance: name}, quietLog())
		}()
	}
	<-done
	<-done
	for _, err := range errs {
		if err != nil {
			t.Fatalf("open: %v", err)
		}
	}
	c, d := spools[0], spools[1]
	if c.Depth()+d.Depth() != 6 || (c.Depth() != 0 && d.Depth() != 0) {
		t.Fatalf("depths c=%d d=%d, want one of them to hold all 6 events and the other none", c.Depth(), d.Depth())
	}
	owner := c
	if d.Depth() > 0 {
		owner = d
	}
	for {
		seg, ok, err := owner.Oldest()
		if err != nil {
			t.Fatalf("oldest: %v", err)
		}
		if !ok {
			break
		}
		if seg.Entries[0].Event.Action != "gone" {
			t.Fatalf("replayed %q, want the abandoned replica's events", seg.Entries[0].Event.Action)
		}
		if err := owner.Remove(seg.Name); err != nil {
			t.Fatalf("remove: %v", err)
		}
	}
	left, _ := filepath.Glob(filepath.Join(root, "*", spoolAdoptedPrefix+"*"))
	if len(left) != 0 {
		t.Fatalf("adopted directories left behind after replay: %v", left)
	}
	if _, err := os.Stat(filepath.Join(root, "pod-gone")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the abandoned directory is still there: %v", err)
	}
}

// Segments from a release that wrote straight into the shared directory
// are taken over like an abandoned replica's, once they are as old.
func TestSpoolAdoptsLegacySegments(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	legacy := filepath.Join(root, "00000000000000000004-000002.ndjson")
	body := `{"at":"2026-03-04T05:06:00Z","event":{"Action":"legacy"}}` + "\n" +
		`{"at":"2026-03-04T05:06:01Z","event":{"Action":"legacy"}}` + "\n"
	if err := os.WriteFile(legacy, []byte(body), 0o600); err != nil {
		t.Fatalf("stage a legacy segment: %v", err)
	}
	fresh, err := OpenSpool(SpoolConfig{Dir: root, Instance: "pod-a"}, quietLog())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if fresh.Depth() != 0 {
		t.Fatalf("depth = %d, want a new legacy segment left to the replica that may still own it", fresh.Depth())
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(legacy, old, old); err != nil {
		t.Fatalf("age the legacy segment: %v", err)
	}
	fresh.AdoptOrphans()
	if fresh.Depth() != 2 {
		t.Fatalf("depth = %d, want the legacy segment's 2 events adopted", fresh.Depth())
	}
	seg, ok, err := fresh.Oldest()
	if err != nil || !ok || len(seg.Entries) != 2 {
		t.Fatalf("oldest = %v %v %v, want the legacy segment", seg, ok, err)
	}
}

func TestSanitizeInstance(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"supermcp-7d9f8c-x2k4q", "supermcp-7d9f8c-x2k4q"},
		{"host.example.com", "host.example.com"},
		{"a/b", "a_b"},
		{"../etc", ""},
		{".hidden", ""},
		{"adopted-pod", ""},
		{"", ""},
	} {
		if got := SanitizeInstance(tc.in); got != tc.want {
			t.Errorf("SanitizeInstance(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
