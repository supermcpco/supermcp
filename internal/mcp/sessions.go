package mcp

import (
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/telemetry"
)

// Sessions for the servers set to stateful.
//
// The SDK keeps each session in the memory of the replica that
// initialised it; there is no store to share them through, so a client has
// to keep reaching the same replica (docs/operations.md, sticky routing).
// The table here is what bounds them: how many one replica holds, how long
// one may sit idle, and closing all of them when the replica drains. The
// SDK knows the sessions; this table knows which server and which caller
// each belongs to, so a session id presented on another server, or by
// another caller, is answered as unknown.

// sessionHeader is the header the Streamable HTTP transport names a
// session with.
const sessionHeader = "Mcp-Session-Id"

var (
	errSessionsFull     = errors.New("this replica holds as many MCP sessions as it may, and all of them are busy")
	errSessionsDraining = errors.New("this replica is shutting down")
)

// SessionOptions bound the sessions one endpoint holds.
type SessionOptions struct {
	// Max is how many sessions the endpoint holds at once. Zero means
	// 5000.
	Max int
	// Idle is how long a session may go without a request. Zero means 15
	// minutes.
	Idle time.Duration
}

type sessionEntry struct {
	id       string
	serverID string
	owner    string
	// srv is the assembled server the session was connected to; the SDK
	// session is found through it when the table has to close one.
	srv      *sdk.Server
	lastSeen time.Time
	// inflight counts the requests on this session that have not yet
	// returned. A session with one is never idle.
	inflight int
}

// sessionTable is the bookkeeping for stateful sessions.
//
// It runs no goroutine of its own while it is empty. The first session
// arms a timer; each sweep closes what has been idle too long and rearms
// the timer while anything is left. close stops it.
type sessionTable struct {
	max     int
	idle    time.Duration
	metrics *telemetry.Metrics
	log     *slog.Logger
	now     func() time.Time

	mu       sync.Mutex
	byID     map[string]*sessionEntry
	reserved int
	closed   bool
	timer    *time.Timer
}

func newSessionTable(o SessionOptions, m *telemetry.Metrics, log *slog.Logger) *sessionTable {
	if o.Max <= 0 {
		o.Max = 5000
	}
	if o.Idle <= 0 {
		o.Idle = 15 * time.Minute
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &sessionTable{max: o.Max, idle: o.Idle, metrics: m, log: log, now: time.Now, byID: map[string]*sessionEntry{}}
}

// ownerOf names the caller a session belongs to. It is who is calling,
// not how: the same person on a refreshed token keeps their session, and
// the permission check on every call reads the credential of that call.
func ownerOf(p *authz.Principal) string {
	return string(p.Kind) + "\x00" + p.ID + "\x00" + p.OrgID
}

// reserve holds a place for a session about to be initialised. When the
// table is full it closes the session idle longest to make room; when
// every session is busy it refuses. The caller settles the reservation
// once the initialise request has returned.
func (t *sessionTable) reserve() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errSessionsDraining
	}
	var victim *sessionEntry
	if len(t.byID)+t.reserved >= t.max {
		for _, e := range t.byID {
			if e.inflight == 0 && (victim == nil || e.lastSeen.Before(victim.lastSeen)) {
				victim = e
			}
		}
		if victim == nil {
			t.mu.Unlock()
			return errSessionsFull
		}
		delete(t.byID, victim.id)
	}
	t.reserved++
	n := len(t.byID)
	t.mu.Unlock()
	t.metrics.SetMCPSessions(n)
	if victim != nil {
		closeSession(victim)
		t.metrics.ObserveMCPSessionClosed(telemetry.SessionClosedCapacity)
	}
	return nil
}

// add records a session the SDK has just created, with its initialise
// request still in flight. It is called when the response headers carry
// the new id, before the client can have read them, so the client's next
// request always finds the session here.
func (t *sessionTable) add(id, serverID, owner string, srv *sdk.Server) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		// Drain began while this session was being initialised. It will
		// not be kept, so it is not counted either.
		closeSession(&sessionEntry{id: id, srv: srv})
		return
	}
	t.byID[id] = &sessionEntry{id: id, serverID: serverID, owner: owner, srv: srv, lastSeen: t.now(), inflight: 1}
	if t.timer == nil {
		t.timer = time.AfterFunc(t.sweepEvery(), t.sweep)
	}
	n := len(t.byID)
	t.mu.Unlock()
	t.metrics.SetMCPSessions(n)
}

// settle ends a reservation. id is the session it became, or empty when
// the initialise request did not create one.
func (t *sessionTable) settle(id string) {
	t.mu.Lock()
	t.reserved--
	t.mu.Unlock()
	if id != "" {
		t.end(id)
	}
}

// begin marks a request on an existing session. It reports false for a
// session this table does not hold for this server and this caller, which
// the endpoint answers as unknown: 404, and the client initialises again.
func (t *sessionTable) begin(id, serverID, owner string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.byID[id]
	if e == nil || e.serverID != serverID || e.owner != owner {
		return false
	}
	e.inflight++
	e.lastSeen = t.now()
	return true
}

// end marks a request on a session finished.
func (t *sessionTable) end(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.byID[id]; e != nil {
		e.inflight--
		e.lastSeen = t.now()
	}
}

// forget drops a session the SDK has already closed.
func (t *sessionTable) forget(id, reason string) {
	t.mu.Lock()
	_, ok := t.byID[id]
	delete(t.byID, id)
	n := len(t.byID)
	t.mu.Unlock()
	if ok {
		t.metrics.SetMCPSessions(n)
		t.metrics.ObserveMCPSessionClosed(reason)
	}
}

// len reports how many sessions the table holds.
func (t *sessionTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byID)
}

// sweepEvery is how often idle sessions are looked for: often enough that
// a session outlives its limit by a quarter at most, and at least once a
// minute.
func (t *sessionTable) sweepEvery() time.Duration {
	return min(t.idle/4, time.Minute)
}

// sweep closes the sessions idle past the limit and forgets the ones the
// SDK has already closed. It runs on the timer's goroutine and rearms the
// timer while there is anything left to watch.
func (t *sessionTable) sweep() {
	defer func() {
		// A panic here would take the process down from a goroutine
		// nobody is waiting on.
		if r := recover(); r != nil {
			t.log.Error("mcp session sweep panicked", "panic", r)
		}
	}()
	now := t.now()
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	// The sessions the SDK still holds, per assembled server, read once.
	live := map[*sdk.Server]map[string]bool{}
	for _, e := range t.byID {
		if live[e.srv] == nil {
			ids := map[string]bool{}
			for ss := range e.srv.Sessions() {
				ids[ss.ID()] = true
			}
			live[e.srv] = ids
		}
	}
	var idle []*sessionEntry
	gone := 0
	for id, e := range t.byID {
		switch {
		case !live[e.srv][id]:
			delete(t.byID, id)
			gone++
		case e.inflight == 0 && now.Sub(e.lastSeen) >= t.idle:
			delete(t.byID, id)
			idle = append(idle, e)
		}
	}
	n := len(t.byID)
	if n > 0 {
		t.timer.Reset(t.sweepEvery())
	} else {
		t.timer = nil
	}
	t.mu.Unlock()

	t.metrics.SetMCPSessions(n)
	for _, e := range idle {
		closeSession(e)
		t.metrics.ObserveMCPSessionClosed(telemetry.SessionClosedIdle)
	}
	for range gone {
		t.metrics.ObserveMCPSessionClosed(telemetry.SessionClosedGone)
	}
}

// close closes every session and refuses new ones. It returns how many
// it closed.
func (t *sessionTable) close() int {
	t.mu.Lock()
	t.closed = true
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	all := make([]*sessionEntry, 0, len(t.byID))
	for _, e := range t.byID {
		all = append(all, e)
	}
	t.byID = map[string]*sessionEntry{}
	t.mu.Unlock()

	t.metrics.SetMCPSessions(0)
	for _, e := range all {
		closeSession(e)
		t.metrics.ObserveMCPSessionClosed(telemetry.SessionClosedShutdown)
	}
	return len(all)
}

// closeSession ends the SDK's session. Closing it cancels whatever it is
// still running and removes it from the SDK's own table, so the client's
// next request is answered 404.
func closeSession(e *sessionEntry) {
	for ss := range e.srv.Sessions() {
		if ss.ID() == e.id {
			_ = ss.Close()
			return
		}
	}
}

// headerHook calls hook once, just before the response headers go out.
// It is how the table learns a new session's id before the client does.
type headerHook struct {
	http.ResponseWriter
	hook func(http.Header, int)
	done bool
}

func (h *headerHook) WriteHeader(code int) {
	if !h.done {
		h.done = true
		h.hook(h.Header(), code)
	}
	h.ResponseWriter.WriteHeader(code)
}

func (h *headerHook) Write(b []byte) (int, error) {
	if !h.done {
		h.WriteHeader(http.StatusOK)
	}
	return h.ResponseWriter.Write(b)
}

// Flush keeps a streamed response streaming.
func (h *headerHook) Flush() {
	if f, ok := h.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the writer underneath.
func (h *headerHook) Unwrap() http.ResponseWriter { return h.ResponseWriter }
