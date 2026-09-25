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

// Why a new session was refused. The first two are the caller's or the
// workspace's own limit (429); the last is the replica's (503).
var (
	errCallerFull       = errors.New("you hold as many MCP sessions on this replica as one caller may, and all of them are busy")
	errOrgFull          = errors.New("this workspace holds as many MCP sessions on this replica as it may, and all of them are busy")
	errSessionsFull     = errors.New("this replica holds as many MCP sessions as it may, and none it could close is idle")
	errSessionsDraining = errors.New("this replica is shutting down")
)

// SessionOptions bound the sessions one endpoint holds.
type SessionOptions struct {
	// Max is how many sessions the endpoint holds at once. Zero means
	// 5000.
	Max int
	// PerCaller is how many one caller (one credential) may hold. Zero
	// means 16.
	PerCaller int
	// PerOrg is how many one workspace may hold. Zero means Max/10, and at
	// least one.
	PerOrg int
	// Idle is how long a session may go without a request. Zero means 15
	// minutes.
	Idle time.Duration
	// MaxAge is how long a session may last however busy it is. Zero
	// means 12 hours.
	MaxAge time.Duration
}

type sessionEntry struct {
	id       string
	serverID string
	owner    string
	org      string
	// srv is the assembled server the session was connected to; the SDK
	// session is found through it when the table has to close one.
	srv      *sdk.Server
	created  time.Time
	lastSeen time.Time
	// inflight counts the requests on this session that have not yet
	// returned. A session with one is never idle, and never closed to
	// make room.
	inflight int
}

// sessionTable is the bookkeeping for stateful sessions.
//
// It runs no goroutine of its own while it is empty. The first session
// arms a timer; each sweep closes what has been idle or open too long and
// rearms the timer while anything is left. close stops it.
//
// Room is made fairly. A caller at its own limit can only displace its
// own sessions, and a workspace at its limit only its own; when the
// replica as a whole is full, only a caller or a workspace holding more
// than its share of the table loses a session. So one tenant filling the
// table closes its own sessions, not everybody else's, and a tenant whose
// sessions are all busy is refused rather than making room elsewhere.
type sessionTable struct {
	max, perCaller, perOrg int
	idle, maxAge           time.Duration
	metrics                *telemetry.Metrics
	log                    *slog.Logger
	now                    func() time.Time

	mu   sync.Mutex
	byID map[string]*sessionEntry
	// held counts sessions and reservations per owner and per workspace.
	byOwner, byOrg map[string]int
	reserved       int
	closed         bool
	timer          *time.Timer
}

func newSessionTable(o SessionOptions, m *telemetry.Metrics, log *slog.Logger) *sessionTable {
	if o.Max <= 0 {
		o.Max = 5000
	}
	if o.PerCaller <= 0 {
		o.PerCaller = 16
	}
	if o.PerOrg <= 0 {
		o.PerOrg = max(o.Max/10, 1)
	}
	if o.Idle <= 0 {
		o.Idle = 15 * time.Minute
	}
	if o.MaxAge <= 0 {
		o.MaxAge = 12 * time.Hour
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &sessionTable{max: o.Max, perCaller: o.PerCaller, perOrg: o.PerOrg, idle: o.Idle, maxAge: o.MaxAge,
		metrics: m, log: log, now: time.Now,
		byID: map[string]*sessionEntry{}, byOwner: map[string]int{}, byOrg: map[string]int{}}
}

// ownerOf names who a session belongs to: the person or account, and the
// credential they called with. An API key is itself; an OAuth access
// token is its client, which survives the token being refreshed but not
// another client of the same person picking the session up. A browser
// session or anything else is its authentication method.
func ownerOf(p *authz.Principal) string {
	cred := "method:" + p.AuthMethod
	switch {
	case p.APIKeyID != "":
		cred = "key:" + p.APIKeyID
	case p.ClientID != "":
		cred = "client:" + p.ClientID
	}
	return string(p.Kind) + "\x00" + p.ID + "\x00" + p.OrgID + "\x00" + cred
}

// reserve holds a place for a session about to be initialised by owner in
// org, closing one of the sessions the rules above allow to make room.
// The caller settles the reservation once the initialise request has
// returned.
func (t *sessionTable) reserve(owner, org string) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errSessionsDraining
	}
	victim, err := t.room(owner, org)
	if err != nil {
		t.mu.Unlock()
		return err
	}
	if victim != nil {
		t.remove(victim)
	}
	t.reserved++
	t.byOwner[owner]++
	t.byOrg[org]++
	n := len(t.byID)
	t.mu.Unlock()
	t.metrics.SetMCPSessions(n)
	if victim != nil {
		closeSession(victim)
		t.metrics.ObserveMCPSessionClosed(telemetry.SessionClosedCapacity)
	}
	return nil
}

// room picks the session to close so that owner may open one, or says
// why none may be. Called with t.mu held.
func (t *sessionTable) room(owner, org string) (*sessionEntry, error) {
	oldest := func(ok func(e *sessionEntry) bool) *sessionEntry {
		var v *sessionEntry
		for _, e := range t.byID {
			if e.inflight == 0 && ok(e) && (v == nil || e.lastSeen.Before(v.lastSeen)) {
				v = e
			}
		}
		return v
	}
	switch {
	case t.byOwner[owner] >= t.perCaller:
		if v := oldest(func(e *sessionEntry) bool { return e.owner == owner }); v != nil {
			return v, nil
		}
		return nil, errCallerFull
	case t.byOrg[org] >= t.perOrg:
		if v := oldest(func(e *sessionEntry) bool { return e.org == org }); v != nil {
			return v, nil
		}
		return nil, errOrgFull
	case len(t.byID)+t.reserved >= t.max:
		// A share is the table divided among those holding a place in it,
		// the newcomer included.
		owners, orgs := len(t.byOwner), len(t.byOrg)
		if t.byOwner[owner] == 0 {
			owners++
		}
		if t.byOrg[org] == 0 {
			orgs++
		}
		ownerShare, orgShare := t.max/owners, t.max/orgs
		if v := oldest(func(e *sessionEntry) bool {
			// A caller may always give up one of its own; anyone else's
			// only if they hold more than their share.
			return e.owner == owner || t.byOwner[e.owner] > ownerShare || t.byOrg[e.org] > orgShare
		}); v != nil {
			return v, nil
		}
		return nil, errSessionsFull
	}
	return nil, nil
}

// remove takes a session out of the table. Called with t.mu held.
func (t *sessionTable) remove(e *sessionEntry) {
	delete(t.byID, e.id)
	t.release(e.owner, e.org)
}

// release gives back one place held by owner in org. Called with t.mu held.
func (t *sessionTable) release(owner, org string) {
	if t.byOwner[owner]--; t.byOwner[owner] <= 0 {
		delete(t.byOwner, owner)
	}
	if t.byOrg[org]--; t.byOrg[org] <= 0 {
		delete(t.byOrg, org)
	}
}

// add records a session the SDK has just created, with its initialise
// request still in flight. It is called when the response headers carry
// the new id, before the client can have read them, so the client's next
// request always finds the session here. The reservation's place becomes
// the session's.
func (t *sessionTable) add(id, serverID, owner, org string, srv *sdk.Server) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		// Drain began while this session was being initialised. It will
		// not be kept, so it is not counted either.
		closeSession(&sessionEntry{id: id, srv: srv})
		return
	}
	now := t.now()
	t.byID[id] = &sessionEntry{id: id, serverID: serverID, owner: owner, org: org, srv: srv,
		created: now, lastSeen: now, inflight: 1}
	// The place is the session's now, not the reservation's.
	t.byOwner[owner]++
	t.byOrg[org]++
	if t.timer == nil {
		t.timer = time.AfterFunc(t.sweepEvery(), t.sweep)
	}
	n := len(t.byID)
	t.mu.Unlock()
	t.metrics.SetMCPSessions(n)
}

// settle ends a reservation. id is the session it became, or empty when
// the initialise request did not create one.
func (t *sessionTable) settle(owner, org, id string) {
	t.mu.Lock()
	t.reserved--
	t.release(owner, org)
	t.mu.Unlock()
	if id != "" {
		t.end(id)
	}
}

// begin marks a request on an existing session. It reports false for a
// session this table does not hold for this server and this caller, and
// for one past its maximum age, which it closes; the endpoint answers
// both as unknown: 404, and the client initialises again.
func (t *sessionTable) begin(id, serverID, owner string) bool {
	t.mu.Lock()
	e := t.byID[id]
	if e == nil || e.serverID != serverID || e.owner != owner {
		t.mu.Unlock()
		return false
	}
	now := t.now()
	if now.Sub(e.created) >= t.maxAge {
		expired := e.inflight == 0
		if expired {
			t.remove(e)
		}
		n := len(t.byID)
		t.mu.Unlock()
		// A request still running keeps the session until it returns; the
		// sweep closes it then. This one is refused either way.
		if expired {
			t.metrics.SetMCPSessions(n)
			closeSession(e)
			t.metrics.ObserveMCPSessionClosed(telemetry.SessionClosedExpired)
		}
		return false
	}
	e.inflight++
	e.lastSeen = now
	t.mu.Unlock()
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
	e, ok := t.byID[id]
	if ok {
		t.remove(e)
	}
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

// sweep closes the sessions idle past the limit or open past the maximum
// age, and forgets the ones the SDK has already closed. It runs on the timer's goroutine and rearms the
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
	var idle, expired []*sessionEntry
	gone := 0
	for id, e := range t.byID {
		switch {
		case !live[e.srv][id]:
			t.remove(e)
			gone++
		case e.inflight == 0 && now.Sub(e.created) >= t.maxAge:
			t.remove(e)
			expired = append(expired, e)
		case e.inflight == 0 && now.Sub(e.lastSeen) >= t.idle:
			t.remove(e)
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
	for _, e := range expired {
		closeSession(e)
		t.metrics.ObserveMCPSessionClosed(telemetry.SessionClosedExpired)
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
	t.byOwner, t.byOrg = map[string]int{}, map[string]int{}
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
