// Package audit records what happened, in a form an auditor can trust.
//
// Every event carries the hash of the one before it, so removing or
// editing a row breaks the chain at a detectable point. Appends are
// serialised through one writer per process and an advisory lock across
// replicas, because a hash chain has to be built in order.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// Category groups events.
const (
	CategoryAuth     = "auth"
	CategoryAdmin    = "admin"
	CategoryTool     = "tool"
	CategoryAuthz    = "authz"
	CategorySecrets  = "secrets"
	CategorySystem   = "system"
	CategoryGovernan = "governance"
)

// Outcome values.
const (
	Success = "success"
	Failure = "failure"
	Denied  = "denied"
)

// chainLockID serialises appends across replicas.
const chainLockID int64 = 0xA0D17

// Event is one record.
type Event struct {
	OrgID         string
	Category      string
	Action        string
	Outcome       string
	ActorKind     string
	ActorID       string
	ActorDisplay  string
	OnBehalfOf    string
	TargetKind    string
	TargetID      string
	TargetDisplay string
	RequestID     string
	SessionID     string
	IP            string
	UserAgent     string
	Diff          any
	Payload       any
	Meta          map[string]any
}

// What a writer does when the database will not take an event.
const (
	// UnavailableBlock makes the caller wait, and fail if it cannot.
	UnavailableBlock = "block"
	// UnavailableDegrade drops the event and counts it.
	UnavailableDegrade = "degrade"
	// UnavailableSpool writes the event to local disk and replays it when
	// the database comes back.
	UnavailableSpool = "spool"
)

const (
	defaultSpoolDir      = "/var/lib/supermcp/audit-spool"
	defaultSpoolMaxBytes = 256 << 20
)

// PayloadMode is the org's policy for storing tool payloads.
type PayloadMode string

const (
	PayloadNone     PayloadMode = "none"
	PayloadMetadata PayloadMode = "metadata"
	PayloadMasked   PayloadMode = "masked"
	PayloadFull     PayloadMode = "full"
)

// Options tune the writer.
type Options struct {
	// Buffer is how many events may queue before Emit blocks.
	Buffer int
	// MaxPayloadBytes caps a stored payload.
	MaxPayloadBytes int
	// OnUnavailable decides what happens when the database refuses the
	// append: "block" makes the caller fail, "degrade" drops the event
	// after logging it, "spool" holds it on local disk until the database
	// comes back.
	OnUnavailable string
	// SpoolDir is where spooled events wait. Only "spool" reads it.
	SpoolDir string
	// SpoolMaxBytes bounds that directory. Past the bound events are
	// dropped and counted, because filling the disk stops the gateway
	// recording anything at all.
	SpoolMaxBytes int64
	// Now supplies the write time. It exists for tests, which need to age a
	// stream: the timestamp is covered by the hash, so editing it in the
	// database is tampering and is caught, as it should be.
	Now func() time.Time
}

// OptionsFromEnv reads the writer's settings from the environment, so that
// a deployment changes them without a code change.
//
//	SUPERMCP_AUDIT_ON_UNAVAILABLE   block | degrade (default) | spool
//	SUPERMCP_AUDIT_SPOOL_DIR        /var/lib/supermcp/audit-spool
//	SUPERMCP_AUDIT_SPOOL_MAX_BYTES  268435456
func OptionsFromEnv(get func(string) string) Options {
	o := Options{OnUnavailable: get("SUPERMCP_AUDIT_ON_UNAVAILABLE"), SpoolDir: get("SUPERMCP_AUDIT_SPOOL_DIR")}
	if n, err := strconv.ParseInt(get("SUPERMCP_AUDIT_SPOOL_MAX_BYTES"), 10, 64); err == nil && n > 0 {
		o.SpoolMaxBytes = n
	}
	return o
}

// Writer appends events.
type Writer struct {
	db   *tenant.DB
	log  *slog.Logger
	opts Options

	queue  chan *pending
	wg     sync.WaitGroup
	closed chan struct{}
	once   sync.Once
	// dropped counts events the queue could not take. They are reported
	// into the stream itself on the next successful append, because a gap
	// nobody records is indistinguishable from a quiet period.
	dropped atomic.Int64

	// spool holds events the database refused, when the organisation has
	// asked for that rather than blocking or dropping. It is nil otherwise.
	spool *Spool
	// overflow is where an event goes when the queue is full and there is
	// a spool: the writer goroutine picks it up on its next flush, behind
	// what is already queued, so nothing overtakes anything.
	omu      sync.Mutex
	overflow []*pending
}

// QueueDepth reports how many events are waiting to be written. A depth
// that stays high is the warning before events start being dropped.
func (w *Writer) QueueDepth() int {
	if w == nil {
		return 0
	}
	return len(w.queue)
}

// Dropped reports how many events have been discarded and not yet
// reported into the stream.
func (w *Writer) Dropped() int64 {
	if w == nil {
		return 0
	}
	return w.dropped.Load()
}

// SpoolDepth reports how many events are waiting on disk for a database
// that would not take them. Zero when nothing is spooled, and zero when
// the writer does not spool at all.
func (w *Writer) SpoolDepth() int {
	if w == nil {
		return 0
	}
	return w.spool.Depth()
}

type pending struct {
	event *Event
	// at is when the writer accepted the event. It matters only for an
	// event that ends up on disk, whose row is stamped when it finally
	// reaches the chain.
	at   time.Time
	done chan error
}

// NewWriter starts the append goroutine.
func NewWriter(db *tenant.DB, log *slog.Logger, opts Options) *Writer {
	if opts.Buffer <= 0 {
		opts.Buffer = 256
	}
	if opts.MaxPayloadBytes <= 0 {
		opts.MaxPayloadBytes = 64 << 10
	}
	if opts.OnUnavailable == "" {
		opts.OnUnavailable = UnavailableDegrade
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	w := &Writer{db: db, log: log, opts: opts, queue: make(chan *pending, opts.Buffer), closed: make(chan struct{})}
	if opts.OnUnavailable == UnavailableSpool {
		dir := opts.SpoolDir
		if dir == "" {
			dir = defaultSpoolDir
		}
		spool, err := OpenSpool(dir, opts.SpoolMaxBytes, log)
		if err != nil {
			// A spool that cannot be opened is a misconfiguration, not a
			// reason to refuse to start: the gateway still records
			// everything the database takes, and says loudly what it has
			// lost the ability to do.
			log.Error("the audit spool could not be opened; events the database refuses will be dropped instead",
				"dir", dir, "err", err)
		} else {
			w.spool = spool
		}
	}
	w.wg.Add(1)
	go w.run()
	return w
}

// Close drains the queue.
func (w *Writer) Close() {
	w.once.Do(func() {
		close(w.queue)
		w.wg.Wait()
		close(w.closed)
	})
}

// Sink is what the rest of the system depends on. A nil *Writer satisfies
// it and discards events, so a caller never needs to check.
type Sink interface {
	Emit(ctx context.Context, e Event)
}

// Emit queues an event. It does not wait for the append: audit must not
// add latency to the request path. Delivery failures are logged, and with
// OnUnavailable "block" the next Emit reports them.
func (w *Writer) Emit(ctx context.Context, e Event) {
	if w == nil {
		return
	}
	p := &pending{event: &e, at: w.opts.Now().UTC()}
	select {
	case w.queue <- p:
	default:
		// The queue is full: the database is slow or down.
		switch w.opts.OnUnavailable {
		case UnavailableBlock:
			select {
			case w.queue <- p:
			case <-ctx.Done():
				w.log.Error("audit append abandoned", "action", e.Action, "err", ctx.Err())
			}
			return
		case UnavailableSpool:
			if w.park(p) {
				return
			}
		}
		w.dropped.Add(1)
		w.log.Error("audit event dropped: the queue is full", "action", e.Action, "org", e.OrgID)
	}
}

// park holds an event the queue could not take until the writer goroutine
// can put it on disk. It is bounded by the same number as the queue, so a
// database that is away does not turn into unbounded memory; past that the
// caller counts the loss.
func (w *Writer) park(p *pending) bool {
	if w.spool == nil {
		return false
	}
	w.omu.Lock()
	defer w.omu.Unlock()
	if len(w.overflow) >= w.opts.Buffer {
		return false
	}
	w.overflow = append(w.overflow, p)
	return true
}

// takeOverflow hands the parked events to the writer goroutine. They go
// behind whatever the queue held, which is the order they were accepted
// in: an event only parks once the queue is full of older ones.
func (w *Writer) takeOverflow() []*pending {
	w.omu.Lock()
	defer w.omu.Unlock()
	if len(w.overflow) == 0 {
		return nil
	}
	out := w.overflow
	w.overflow = nil
	return out
}

// EmitSync appends immediately and reports the result. Used by tests and
// by callers that must know the record landed.
func (w *Writer) EmitSync(ctx context.Context, e Event) error {
	if w == nil {
		return nil
	}
	return w.append(ctx, []*Event{&e})
}

// Flush waits for everything queued so far to be written. Tests read the
// stream straight after acting on it; nothing else should need this.
func (w *Writer) Flush(ctx context.Context) error {
	if w == nil {
		return nil
	}
	done := make(chan error, 1)
	select {
	case w.queue <- &pending{event: nil, done: done}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *Writer) run() {
	defer w.wg.Done()
	batch := make([]*pending, 0, 64)
	waiters := make([]*pending, 0, 64)
	flush := func() {
		batch = append(batch, w.takeOverflow()...)
		var err error
		// A flush with nothing to write is still worth making when the
		// spool is holding events: it is how a recovered database is
		// noticed while the gateway is quiet.
		if len(batch) > 0 || !w.spool.Empty() {
			if err = w.write(context.Background(), batch); err != nil {
				w.log.Error("audit append failed", "events", len(batch), "spooled", w.SpoolDepth(), "err", err)
			}
		}
		for _, p := range waiters {
			if p.done != nil {
				p.done <- err
			}
		}
		batch = batch[:0]
		waiters = waiters[:0]
	}
	timer := time.NewTicker(200 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case p, ok := <-w.queue:
			if !ok {
				flush()
				return
			}
			if p.event != nil {
				batch = append(batch, p)
			}
			waiters = append(waiters, p)
			// A barrier carries no event and asks to write what is queued.
			if p.event == nil || len(batch) >= 200 {
				flush()
			}
		case <-timer.C:
			flush()
		}
	}
}

// write puts a batch in the chain, replaying whatever the spool is
// holding first.
//
// The order is the whole point. Once anything is on disk, everything that
// follows goes on disk too until the backlog has drained, so a spooled
// event cannot be overtaken by one that was written after it. That is also
// why a failed replay spools the batch rather than trying to append it:
// appending it would put it in front of the events still waiting.
func (w *Writer) write(ctx context.Context, batch []*pending) error {
	if w.spool == nil {
		if len(batch) == 0 {
			return nil
		}
		return w.append(ctx, eventsOf(batch))
	}
	if !w.spool.Empty() {
		if err := w.replay(ctx); err != nil {
			return w.hold(batch, err)
		}
	}
	if len(batch) == 0 {
		return nil
	}
	if err := w.append(ctx, eventsOf(batch)); err != nil {
		return w.hold(batch, err)
	}
	return nil
}

// hold puts a batch the database would not take on disk. The original
// cause is still returned: a caller waiting on Flush is told the append
// did not happen, and the events are not lost while it decides what to do
// about that.
func (w *Writer) hold(batch []*pending, cause error) error {
	if len(batch) == 0 {
		return cause
	}
	entries := make([]spoolEntry, len(batch))
	for i, p := range batch {
		at := p.at
		if at.IsZero() {
			at = w.opts.Now().UTC()
		}
		entries[i] = spoolEntry{At: at, Event: *p.event}
	}
	if err := w.spool.Write(entries); err != nil {
		w.dropped.Add(int64(len(batch)))
		w.log.Error("audit events dropped: the database refused them and the spool would not take them",
			"events", len(batch), "cause", cause, "err", err)
		return errors.Join(cause, err)
	}
	w.log.Warn("audit events spooled to disk until the database takes them",
		"events", len(batch), "depth", w.spool.Depth(), "cause", cause)
	return cause
}

// replay puts what is on disk back into the chain, oldest segment first
// and through the same append path as everything else, so a spooled event
// is hashed and linked exactly as it would have been.
//
// A segment is removed only once its append has committed. A crash in
// between therefore repeats a segment: a duplicate event is visible in the
// stream and says what it is, which is the better of the two failures.
func (w *Writer) replay(ctx context.Context) error {
	for {
		seg, ok, err := w.spool.Oldest()
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if len(seg.Entries) > 0 {
			events := make([]*Event, 0, len(seg.Entries))
			for i := range seg.Entries {
				e := seg.Entries[i].Event
				e.Meta = spooledMeta(e.Meta, seg.Entries[i].At)
				events = append(events, &e)
			}
			if err := w.append(ctx, events); err != nil {
				return err
			}
		}
		if err := w.spool.Remove(seg.Name); err != nil {
			return err
		}
	}
}

// spooledMeta records that an event waited on disk, and when it happened.
//
// The row's own timestamp stays the moment it reached the chain. Backdating
// it would be worse than the inaccuracy it fixes: retention decides what to
// delete by age, and a row that can be given an old timestamp is a row that
// can drag the whole stream into a cut that then looks entirely lawful. The
// real time therefore lives in the event's content, which the chain covers
// just as firmly.
func spooledMeta(meta map[string]any, at time.Time) map[string]any {
	out := make(map[string]any, len(meta)+2)
	for k, v := range meta {
		out[k] = v
	}
	out["spooled"] = true
	out["occurredAt"] = at.UTC().Format(time.RFC3339Nano)
	return out
}

func eventsOf(batch []*pending) []*Event {
	out := make([]*Event, 0, len(batch))
	for _, p := range batch {
		out = append(out, p.event)
	}
	return out
}

// append writes a batch in one transaction, continuing the hash chain.
func (w *Writer) append(ctx context.Context, events []*Event) error {
	return w.db.Bypass(ctx, "audit-append", func(tx pgx.Tx) error {
		// Serialise with other replicas for the length of the transaction.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", chainLockID); err != nil {
			return err
		}
		var prev []byte
		err := tx.QueryRow(ctx, `SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&prev)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if prev == nil {
			prev = make([]byte, 32) // genesis
		}
		// Report any loss before the events that followed it, so the gap
		// sits in the right place in the record.
		if n := w.dropped.Swap(0); n > 0 {
			events = append([]*Event{{
				Category: CategorySystem, Action: "audit.events_dropped", Outcome: Failure,
				ActorKind: "system", Meta: map[string]any{"events": n,
					"reason": "the audit queue was full; these events were not recorded"},
			}}, events...)
		}
		for _, e := range events {
			row, err := w.rowFor(e)
			if err != nil {
				return err
			}
			row.prevHash = prev
			row.contentHash = ContentHash(row.diff, row.payload, row.meta)
			row.hash = chainHash(prev, row)
			if _, err := tx.Exec(ctx, `INSERT INTO audit_events
				(id, ts, organization_id, category, action, outcome, actor_kind, actor_id, actor_display, on_behalf_of,
				 target_kind, target_id, target_display, request_id, session_id, ip, user_agent, diff, payload, meta,
				 content_hash, prev_hash, hash)
				VALUES ($1,$2,NULLIF($3,''),$4,$5,$6,$7,NULLIF($8,''),$9,NULLIF($10,''),NULLIF($11,''),NULLIF($12,''),$13,
				        NULLIF($14,''),NULLIF($15,''),$16,NULLIF($17,''),$18,$19,$20,$21,$22,$23)`,
				row.id, row.ts, e.OrgID, e.Category, e.Action, e.Outcome, e.ActorKind, e.ActorID, e.ActorDisplay, e.OnBehalfOf,
				e.TargetKind, e.TargetID, e.TargetDisplay, e.RequestID, e.SessionID, row.ip, e.UserAgent,
				row.diff, row.payload, row.meta, row.contentHash, row.prevHash, row.hash); err != nil {
				return err
			}
			prev = row.hash
		}
		return nil
	})
}

type row struct {
	id                  uuid.UUID
	ts                  time.Time
	diff, payload, meta []byte
	ip                  *netip.Addr
	contentHash         []byte
	prevHash, hash      []byte
	category, action    string
	outcome, actorKind  string
	actorID, targetKind string
	targetID, orgID     string
}

func (w *Writer) rowFor(e *Event) (*row, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	// Postgres keeps microseconds, so the value that comes back is not the
	// one that went in unless it is truncated here first. A hash over a
	// precision the database cannot store would fail on every read.
	r := &row{id: id, ts: w.opts.Now().UTC().Truncate(time.Microsecond),
		category: e.Category, action: e.Action, outcome: e.Outcome,
		actorKind: e.ActorKind, actorID: e.ActorID, targetKind: e.TargetKind, targetID: e.TargetID, orgID: e.OrgID}
	if e.Diff != nil {
		if r.diff, err = w.marshalCapped(e.Diff); err != nil {
			return nil, err
		}
	}
	if e.Payload != nil {
		if r.payload, err = w.marshalCapped(e.Payload); err != nil {
			return nil, err
		}
	}
	if e.Meta != nil {
		if r.meta, err = json.Marshal(e.Meta); err != nil {
			return nil, err
		}
	}
	if a, err := netip.ParseAddr(e.IP); err == nil {
		r.ip = &a
	}
	return r, nil
}

// marshalCapped truncates an oversized value rather than refusing the
// event: losing the record is worse than losing the payload.
func (w *Writer) marshalCapped(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) > w.opts.MaxPayloadBytes {
		return json.Marshal(map[string]any{"_truncated": true, "_bytes": len(b)})
	}
	return b, nil
}

// ContentHash digests the three JSON columns of an event. It is stored
// beside the row and is what the chain covers, so content can later be
// removed under a retention rule or a legal obligation without breaking
// the links either side of it: the digest stays, the content does not.
func ContentHash(diff, payload, meta []byte) []byte {
	h := sha256.New()
	for _, b := range [][]byte{diff, payload, meta} {
		sum := sha256.Sum256(b)
		h.Write(sum[:])
	}
	return h.Sum(nil)
}

// chainHash binds a row to its predecessor. It covers the facts of the
// event and the digest of its content; the columns a lawful edit may touch
// later (legal hold, a pseudonymised display name, scrubbed content) are
// deliberately outside it, so those operations do not invalidate the
// chain.
func chainHash(prev []byte, r *row) []byte {
	h := sha256.New()
	h.Write(prev)
	// The timestamp is inside the hash because it is load-bearing: retention
	// decides what to delete by age, so a row that can be backdated without
	// breaking the chain is a row that can drag the whole stream into a cut
	// that then looks entirely lawful.
	_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00",
		r.id.String(), r.ts.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano), r.orgID, r.category, r.action, r.outcome,
		r.actorKind, r.actorID, r.targetKind, r.targetID)
	h.Write(r.contentHash)
	return h.Sum(nil)
}

// FromPrincipal fills the actor fields from the request principal.
func FromPrincipal(e Event, p *authz.Principal) Event {
	if p == nil {
		e.ActorKind = "anonymous"
		return e
	}
	e.ActorKind = string(p.Kind)
	e.ActorID = p.ID
	e.ActorDisplay = p.Email
	e.SessionID = p.SessionID
	if e.OrgID == "" {
		e.OrgID = p.OrgID
	}
	return e
}
