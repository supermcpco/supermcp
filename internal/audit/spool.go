package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
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

// Spool is a bounded directory of NDJSON segments, oldest first.
type Spool struct {
	dir      string
	maxBytes int64
	log      *slog.Logger

	// mu guards everything below: the writer goroutine writes and replays,
	// while the metric reads the depth from whatever goroutine scrapes it.
	mu     sync.Mutex
	names  []string // segment file names, oldest first
	events int
	bytes  int64
	seq    uint64
}

// OpenSpool prepares the directory and adopts whatever a previous process
// left in it. Adopting rather than clearing is the point: the events in
// there are the ones an outage already stopped from being recorded once.
func OpenSpool(dir string, maxBytes int64, log *slog.Logger) (*Spool, error) {
	if dir == "" {
		return nil, errors.New("the audit spool needs a directory")
	}
	if maxBytes <= 0 {
		maxBytes = defaultSpoolMaxBytes
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create the audit spool directory: %w", err)
	}
	s := &Spool{dir: dir, maxBytes: maxBytes, log: log}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read the audit spool directory: %w", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(name, spoolTempSuffix) {
			// A segment that never finished being written: it was never
			// counted as spooled, so removing it loses nothing.
			_ = os.Remove(filepath.Join(dir, name))
			continue
		}
		if !strings.HasSuffix(name, spoolSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		s.names = append(s.names, name)
		s.bytes += info.Size()
		order, count := parseSegmentName(name)
		s.events += count
		if order >= s.seq {
			s.seq = order + 1
		}
	}
	sort.Strings(s.names)
	if len(s.names) > 0 && log != nil {
		log.Warn("the audit spool holds events from an earlier run; they will be replayed into the chain",
			"dir", dir, "segments", len(s.names), "events", s.events)
	}
	return s, nil
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
	// The name orders the segment and records how many events are in it,
	// so a restart can report the depth without reading every file.
	order := s.seq
	s.seq++
	s.mu.Unlock()

	name := fmt.Sprintf("%020d-%06d%s", order, len(entries), spoolSuffix)
	tmp := filepath.Join(s.dir, name+spoolTempSuffix)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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
	s.syncDir()

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
func (s *Spool) syncDir() {
	d, err := os.Open(s.dir)
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil && s.log != nil {
		s.log.Warn("the audit spool directory could not be synced", "dir", s.dir, "err", err)
	}
}

// parseSegmentName reads the order and the event count back out of a
// segment's name, which is where they are kept so that a restart does not
// have to read every file to know how deep the spool is.
func parseSegmentName(name string) (order uint64, count int) {
	base := strings.TrimSuffix(name, spoolSuffix)
	left, right, ok := strings.Cut(base, "-")
	if !ok {
		return 0, 0
	}
	order, _ = strconv.ParseUint(left, 10, 64)
	n, _ := strconv.Atoi(right)
	return order, n
}
