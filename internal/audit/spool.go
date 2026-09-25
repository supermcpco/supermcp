package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The spool is the third answer to "the database will not take this
// event". Blocking makes the caller wait for a database that may be gone
// for hours; degrading throws the event away and counts it. Spooling puts
// it on local disk, fsynced, and replays it in order when the database
// comes back.
//
// What the spool is not: durable across the loss of the machine, and not a
// queue with delivery guarantees. It is a bounded buffer that survives a
// crash and a restart, which covers the failure this is actually for — the
// database being unreachable for a while.
//
// One volume may be shared by every replica, so each replica keeps to a
// directory of its own, named by its instance identity:
//
//	<dir>/<instance>/.heartbeat                     touched while it lives
//	<dir>/<instance>/<order>-<count>-<instance>.ndjson
//	<dir>/<instance>/adopted-<other>-<nanos>/...    taken over from a dead one
//
// A replica only ever reads files under its own directory. That is the
// claim: a file is replayed by the replica whose directory it is in. A
// replica whose heartbeat is older than the orphan age is taken to be
// gone, and the first live replica to rename its directory into its own
// takes over its files. A rename either happens or does not, so two
// replicas racing for the same orphan cannot both win it.

// ErrSpoolFull is returned when the directory is at its bound. The caller
// counts the loss rather than growing without limit: a spool that fills
// the disk takes the gateway down with it, and a gateway that is down
// records nothing at all.
var ErrSpoolFull = errors.New("the audit spool is full")

const (
	spoolSuffix = ".ndjson"
	// spoolTempSuffix marks a segment that is still being written. Only a
	// renamed file is ever replayed, so a crash mid-write leaves rubbish
	// that is cleaned up rather than a half event that is read back.
	spoolTempSuffix = ".tmp"
	// spoolSegmentMax caps how many events one segment holds, because a
	// segment is replayed in one transaction.
	spoolSegmentMax = 200
	// spoolLineMax bounds one line on the way back in. A payload is capped
	// at 64 KiB by the writer, and a line carries one event's worth.
	spoolLineMax = 1 << 20
	// spoolHeartbeat is the file whose modification time says the owner of
	// a directory is alive.
	spoolHeartbeat = ".heartbeat"
	// spoolAdoptedPrefix names a directory taken over from another replica.
	spoolAdoptedPrefix = "adopted-"
	// DefaultSpoolOrphanAge is how long a replica's heartbeat may go
	// unrefreshed before another replica takes over its spooled events.
	DefaultSpoolOrphanAge = 10 * time.Minute
	// minSpoolOrphanAge keeps the orphan age well above the heartbeat
	// interval, so a live replica is never mistaken for a dead one.
	minSpoolOrphanAge = 30 * time.Second
)

// spoolEntry is one event as it waits on disk, with the time it was
// accepted. The time is kept because the row the event eventually becomes
// is stamped when it reaches the chain, not when it happened, and the
// difference has to be recoverable from the record itself.
type spoolEntry struct {
	At    time.Time `json:"at"`
	Event Event     `json:"event"`
}

// segment is one file of spooled events.
type segment struct {
	Name    string
	Entries []spoolEntry
}

// SpoolConfig says where a spool lives and whose it is.
type SpoolConfig struct {
	// Dir is the directory every replica's spool sits under.
	Dir string
	// Instance names this replica. Its segments go in Dir/Instance and
	// carry the name, so two replicas never write the same file.
	Instance string
	// MaxBytes bounds what this replica holds, adopted segments included.
	MaxBytes int64
	// OrphanAge is how old another replica's heartbeat must be before this
	// one takes over its segments. DefaultSpoolOrphanAge when zero, and
	// never less than thirty seconds.
	OrphanAge time.Duration
	// Now is the clock the heartbeat is judged by. time.Now when nil.
	Now func() time.Time
}

// Spool is a bounded directory of NDJSON segments, oldest first.
type Spool struct {
	root      string // the directory shared by every replica
	dir       string // this replica's own directory under it
	instance  string
	maxBytes  int64
	orphanAge time.Duration
	now       func() time.Time
	log       *slog.Logger

	// mu guards everything below: the writer goroutine writes and replays,
	// while the metric reads the depth from whatever goroutine scrapes it.
	mu     sync.Mutex
	names  []string // segment paths relative to dir, oldest first
	events int
	bytes  int64
	order  int64
}

// OpenSpool prepares this replica's directory, adopts whatever a previous
// process under the same name left in it, and takes over the directories
// of replicas that have stopped refreshing their heartbeat. Adopting
// rather than clearing is the point: the events in there are the ones an
// outage already stopped from being recorded once.
func OpenSpool(cfg SpoolConfig, log *slog.Logger) (*Spool, error) {
	if cfg.Dir == "" {
		return nil, errors.New("the audit spool needs a directory")
	}
	instance := SanitizeInstance(cfg.Instance)
	if instance == "" {
		return nil, errors.New("the audit spool needs an instance name")
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultSpoolMaxBytes
	}
	if cfg.OrphanAge <= 0 {
		cfg.OrphanAge = DefaultSpoolOrphanAge
	}
	cfg.OrphanAge = max(cfg.OrphanAge, minSpoolOrphanAge)
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Spool{root: cfg.Dir, dir: filepath.Join(cfg.Dir, instance), instance: instance,
		maxBytes: cfg.MaxBytes, orphanAge: cfg.OrphanAge, now: cfg.Now, log: log}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, fmt.Errorf("create the audit spool directory: %w", err)
	}
	s.Beat()
	if err := s.scan(); err != nil {
		return nil, err
	}
	if len(s.names) > 0 && log != nil {
		log.Warn("the audit spool holds events from an earlier run; they will be replayed into the chain",
			"dir", s.dir, "segments", len(s.names), "events", s.events)
	}
	s.AdoptOrphans()
	return s, nil
}

// scan reads this replica's directory, adopted directories included, into
// the in-memory index.
func (s *Spool) scan() error {
	var names []string
	var events int
	var bytes, next int64
	err := filepath.WalkDir(s.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, spoolTempSuffix) {
			// A segment that never finished being written: it was never
			// counted as spooled, so removing it loses nothing.
			_ = os.Remove(path)
			return nil
		}
		if !strings.HasSuffix(name, spoolSuffix) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil //nolint:nilerr // a file that vanished mid-walk is simply not there
		}
		rel, err := filepath.Rel(s.dir, path)
		if err != nil {
			return err
		}
		names = append(names, rel)
		bytes += info.Size()
		order, count := parseSegmentName(name)
		events += count
		next = max(next, order+1)
		return nil
	})
	if err != nil {
		return fmt.Errorf("read the audit spool directory: %w", err)
	}
	sortSegments(names)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.names, s.events, s.bytes = names, events, bytes
	s.order = max(s.order, next)
	return nil
}

// sortSegments puts this replica's own segments first, in order, then
// each adopted directory's, each in its own order. Order matters within a
// replica's stream, which is the only order a spool ever had.
func sortSegments(names []string) {
	sort.Slice(names, func(i, j int) bool {
		di, dj := filepath.Dir(names[i]), filepath.Dir(names[j])
		if di != dj {
			if di == "." || dj == "." {
				return di == "."
			}
			return di < dj
		}
		return filepath.Base(names[i]) < filepath.Base(names[j])
	})
}

// Beat refreshes this replica's heartbeat, which is what stops another
// replica taking its segments over. The writer calls it well inside the
// orphan age.
func (s *Spool) Beat() {
	if s == nil {
		return
	}
	path := filepath.Join(s.dir, spoolHeartbeat)
	now := s.now()
	if err := os.Chtimes(path, now, now); err == nil {
		return
	}
	// The directory may have been taken over while this replica was
	// stalled for longer than the orphan age; start a fresh one.
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		s.warn("the audit spool directory could not be recreated", err)
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		s.warn("the audit spool heartbeat could not be written", err)
		return
	}
	_ = f.Close()
	_ = os.Chtimes(path, now, now)
}

// BeatEvery is how often Beat has to run for this spool's heartbeat never
// to look stale.
func (s *Spool) BeatEvery() time.Duration {
	if s == nil {
		return 0
	}
	return min(s.orphanAge/4, time.Minute)
}

// AdoptOrphans takes over the directories of replicas whose heartbeat is
// older than the orphan age, and segments left at the top level by a
// release that did not keep per-replica directories. Each is renamed into
// this replica's directory first, and only then read: whoever's rename
// succeeds replays it, and nobody else ever sees it again.
func (s *Spool) AdoptOrphans() {
	if s == nil {
		return
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		s.warn("the shared audit spool directory could not be read", err)
		return
	}
	cutoff := s.now().Add(-s.orphanAge)
	adopted := 0
	for _, e := range entries {
		name := e.Name()
		if name == s.instance || strings.HasPrefix(name, ".") {
			continue
		}
		src := filepath.Join(s.root, name)
		var dst string
		switch {
		case e.IsDir():
			if !s.stale(src, filepath.Join(src, spoolHeartbeat), cutoff) {
				continue
			}
			dst = filepath.Join(s.dir, fmt.Sprintf("%s%s-%d", spoolAdoptedPrefix, name, s.now().UnixNano()))
		case strings.HasSuffix(name, spoolSuffix):
			// A segment from before per-replica directories. A replica of
			// that release may still be running and about to replay it, so
			// it is left alone until it is as old as an orphan.
			if !s.stale(src, src, cutoff) {
				continue
			}
			dir := filepath.Join(s.dir, spoolAdoptedPrefix+"legacy")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				s.warn("the audit spool could not make room for a legacy segment", err)
				continue
			}
			dst = filepath.Join(dir, name)
		default:
			continue
		}
		if err := os.Rename(src, dst); err != nil {
			// Another replica got there first, or it is not ours to take.
			if !errors.Is(err, os.ErrNotExist) {
				s.warn("an orphaned audit spool could not be taken over", err)
			}
			continue
		}
		adopted++
		if s.log != nil {
			s.log.Warn("took over audit events spooled by a replica that is gone; they will be replayed into the chain",
				"from", name, "into", dst)
		}
	}
	if adopted == 0 {
		return
	}
	s.syncDir(s.root)
	before := s.Depth()
	if err := s.scan(); err != nil {
		s.warn("the audit spool could not be re-read after taking over an orphan", err)
		return
	}
	if s.log != nil {
		s.log.Warn("the audit spool now holds adopted events", "events", s.Depth()-before, "depth", s.Depth())
	}
}

// stale reports whether a replica's directory, judged by its heartbeat
// (or, without one, by the directory itself), has not been touched since
// cutoff.
func (s *Spool) stale(dir, heartbeat string, cutoff time.Time) bool {
	info, err := os.Stat(heartbeat)
	if err != nil {
		if info, err = os.Stat(dir); err != nil {
			return false
		}
	}
	return info.ModTime().Before(cutoff)
}

func (s *Spool) warn(msg string, err error) {
	if s.log != nil {
		s.log.Warn(msg, "dir", s.dir, "err", err)
	}
}

// SanitizeInstance makes an instance name safe to use as a directory and
// file name: letters, digits, dot, dash and underscore survive, anything
// else becomes an underscore. The names that would mean something else in
// the spool's layout come back empty.
func SanitizeInstance(id string) string {
	id = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, id)
	if id == "." || id == ".." || strings.HasPrefix(id, ".") || strings.HasPrefix(id, spoolAdoptedPrefix) {
		return ""
	}
	return id
}

// Write puts a batch on disk and returns only once it is durable. The
// segment is written under a temporary name, fsynced, renamed and the
// directory fsynced, so a crash leaves either a whole segment or none.
func (s *Spool) Write(entries []spoolEntry) error {
	for len(entries) > 0 {
		n := min(len(entries), spoolSegmentMax)
		if err := s.writeSegment(entries[:n]); err != nil {
			return err
		}
		entries = entries[n:]
	}
	return nil
}

func (s *Spool) writeSegment(entries []spoolEntry) error {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	for i := range entries {
		if err := enc.Encode(&entries[i]); err != nil {
			return err
		}
	}
	body := buf.String()

	s.mu.Lock()
	if s.bytes+int64(len(body)) > s.maxBytes {
		s.mu.Unlock()
		return fmt.Errorf("%w: %d bytes held, %d allowed", ErrSpoolFull, s.bytes, s.maxBytes)
	}
	// The name orders the segment, records how many events are in it, so
	// a restart can report the depth without reading every file, and says
	// whose it is. The order is the clock where the clock is ahead, so a
	// restart that found the directory empty still names its segments
	// after the ones an earlier run may have left elsewhere.
	order := max(s.order, s.now().UnixNano())
	s.order = order + 1
	s.mu.Unlock()

	name := fmt.Sprintf("%020d-%06d-%s%s", order, len(entries), s.instance, spoolSuffix)
	tmp := filepath.Join(s.dir, name+spoolTempSuffix)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrNotExist) {
		// The directory was taken over while this replica was stalled;
		// start a fresh one and carry on.
		if err = os.MkdirAll(s.dir, 0o700); err == nil {
			f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		}
	}
	if err != nil {
		return err
	}
	if _, err := f.WriteString(body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	// Without the fsync the events are in the page cache, which is exactly
	// what a crash takes with it.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, name)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// The rename itself has to reach the disk, or the segment is durable
	// under a name nothing will look for.
	s.syncDir(s.dir)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.names = append(s.names, name)
	s.bytes += int64(len(body))
	s.events += len(entries)
	return nil
}

// Oldest reads back the segment that has waited longest. A line that will
// not decode is skipped rather than failing the segment: a truncated tail
// is a plausible way for a file to end, and losing the events before it
// too would make a bad situation worse.
func (s *Spool) Oldest() (*segment, bool, error) {
	s.mu.Lock()
	if len(s.names) == 0 {
		s.mu.Unlock()
		return nil, false, nil
	}
	name := s.names[0]
	s.mu.Unlock()

	f, err := os.Open(filepath.Join(s.dir, name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Something removed it underneath us; forget it and move on.
			s.forget(name, 0)
			return nil, false, nil
		}
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	seg := &segment{Name: name}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), spoolLineMax)
	damaged := 0
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e spoolEntry
		if err := json.Unmarshal(line, &e); err != nil {
			damaged++
			continue
		}
		seg.Entries = append(seg.Entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, false, err
	}
	if damaged > 0 && s.log != nil {
		s.log.Error("spooled audit events could not be read back and are lost",
			"segment", name, "events", damaged)
	}
	return seg, true, nil
}

// Remove drops a segment that has been replayed. It is called after the
// append has committed, so a crash in between replays the segment again:
// a duplicate event is visible and explains itself, a lost one does not.
func (s *Spool) Remove(name string) error {
	path := filepath.Join(s.dir, name)
	info, err := os.Stat(path)
	size := int64(0)
	if err == nil {
		size = info.Size()
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s.forget(name, size)
	// An adopted directory goes once its last segment has: everything in
	// it has been replayed. Removing a directory that still holds anything
	// fails, which is the check.
	for dir := filepath.Dir(name); dir != "." && dir != string(filepath.Separator); dir = filepath.Dir(dir) {
		abs := filepath.Join(s.dir, dir)
		_ = os.Remove(filepath.Join(abs, spoolHeartbeat))
		if os.Remove(abs) != nil {
			break
		}
	}
	return nil
}

func (s *Spool) forget(name string, size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, n := range s.names {
		if n != name {
			continue
		}
		s.names = append(s.names[:i], s.names[i+1:]...)
		break
	}
	_, count := parseSegmentName(name)
	s.events -= count
	if s.events < 0 {
		s.events = 0
	}
	s.bytes -= size
	if s.bytes < 0 {
		s.bytes = 0
	}
}

// Depth is how many events are waiting on disk. It is the number an
// operator watches: a depth that is not falling means the database is
// still away, and a depth near the bound means events are about to be
// lost.
func (s *Spool) Depth() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events
}

// Bytes is how much disk the spool is holding.
func (s *Spool) Bytes() int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes
}

// Empty reports whether anything is waiting.
func (s *Spool) Empty() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.names) == 0
}

// syncDir makes the directory's own record of its entries durable. A
// failure is logged and not returned: the segment is already on the disk,
// and refusing the write at this point would spool it twice.
func (s *Spool) syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil && s.log != nil {
		s.log.Warn("the audit spool directory could not be synced", "dir", dir, "err", err)
	}
}

// parseSegmentName reads the order and the event count back out of a
// segment's name, which is where they are kept so that a restart does not
// have to read every file to know how deep the spool is.
//
// A segment is <order>-<count>-<instance>.ndjson; one written before
// per-replica directories is <order>-<count>.ndjson.
func parseSegmentName(name string) (order int64, count int) {
	base := strings.TrimSuffix(filepath.Base(name), spoolSuffix)
	left, right, ok := strings.Cut(base, "-")
	if !ok {
		return 0, 0
	}
	order, _ = strconv.ParseInt(left, 10, 64)
	right, _, _ = strings.Cut(right, "-")
	n, _ := strconv.Atoi(right)
	return order, n
}
