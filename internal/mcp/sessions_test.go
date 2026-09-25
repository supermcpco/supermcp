package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/mcpserver"
)

// These drive the Streamable HTTP endpoint with the SDK's own client,
// from the point where a request's surface has been built: the session
// handling is what is under test, and the surface and the permission
// checks around it are covered against a real database in internal/e2e.

// rig is one endpoint serving one fabricated server, with the caller of
// each request settable between requests.
type rig struct {
	t      *testing.T
	e      *Endpoint
	s      *surface
	url    string
	caller atomic.Pointer[authz.Principal]
	// names, when set, replaces the surface's names for the next requests,
	// as a permission taken away would.
	names atomic.Pointer[map[string]bool]
	// deadline, when set, bounds each request, as the router's timeout does.
	deadline atomic.Int64
	clock    *fakeClock
	// release lets a call to the "hold" tool return; stopped reports how
	// it did.
	release chan struct{}
	holding chan struct{}
	stopped chan error
}

// user is a caller on an API key of their own in an organisation.
func user(id, org, key string) *authz.Principal {
	return &authz.Principal{Kind: authz.KindUser, ID: id, OrgID: org, AuthMethod: "api_key", APIKeyID: key}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newRig(t *testing.T, mode string, opts SessionOptions) *rig {
	t.Helper()
	r := &rig{t: t, e: New(Deps{Version: "test", Sessions: opts}), clock: &fakeClock{now: time.Unix(1_700_000_000, 0)},
		release: make(chan struct{}), holding: make(chan struct{}, 8), stopped: make(chan error, 8)}
	r.e.sessions.now = r.clock.Now
	r.s = fabricate(t, 3)
	r.s.server.Sessions = mode
	r.s.byName = map[string]visibleTool{}
	for _, vt := range r.s.tools {
		r.s.byName[vt.tool.Name] = vt
	}
	r.s.mcp = r.e.assemble(r.s)
	// Two tools that stand in for a real one: whoami reports the caller
	// the handler sees, hold waits until the test lets it go.
	for _, name := range []string{"whoami", "hold"} {
		r.s.names[name] = true
	}
	r.s.mcp.AddTool(&sdk.Tool{Name: "whoami", InputSchema: map[string]any{"type": "object"}},
		func(ctx context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			p, _ := authz.From(ctx)
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: p.ID + "/" + strings.Join(p.Scopes, ",")}}}, nil
		})
	r.s.mcp.AddTool(&sdk.Tool{Name: "hold", InputSchema: map[string]any{"type": "object"}},
		func(ctx context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			r.holding <- struct{}{}
			select {
			case <-r.release:
				r.stopped <- nil
			case <-ctx.Done():
				r.stopped <- ctx.Err()
			}
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "released"}}}, nil
		})
	r.caller.Store(user("u_1", "org_bench", "k_1"))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// What serve does once buildSurface has succeeded: a surface of
		// the request's own, sharing the assembled server.
		ctx := authz.WithPrincipal(req.Context(), r.caller.Load())
		if d := r.deadline.Load(); d > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(d))
			defer cancel()
		}
		names := r.s.names
		if n := r.names.Load(); n != nil {
			names = *n
		}
		s := &surface{server: r.s.server, names: names, byName: r.s.byName, mcp: r.s.mcp}
		r.e.dispatch(w, req.WithContext(ctx), s)
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(r.e.Close)
	r.url = ts.URL
	return r
}

func (r *rig) connect(ctx context.Context) *sdk.ClientSession {
	r.t.Helper()
	cs, err := r.tryConnect(ctx)
	if err != nil {
		r.t.Fatalf("connect: %v", err)
	}
	r.t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func (r *rig) tryConnect(ctx context.Context) (*sdk.ClientSession, error) {
	c := sdk.NewClient(&sdk.Implementation{Name: "sessions-test", Version: "1"}, nil)
	// DisableStandaloneSSE: neither mode offers the GET stream, and the
	// client would otherwise log the 405 it gets for asking.
	return c.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: r.url, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
}

// post sends one raw JSON-RPC message and returns the status.
func (r *rig) post(ctx context.Context, sessionID, body string) (int, http.Header) {
	r.t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, strings.NewReader(body))
	if err != nil {
		r.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set(sessionHeader, sessionID)
		req.Header.Set("Mcp-Protocol-Version", "2025-06-18")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header
}

func whoami(t *testing.T, ctx context.Context, cs *sdk.ClientSession) string {
	t.Helper()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "whoami"})
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	return res.Content[0].(*sdk.TextContent).Text
}

const toolsList = `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`

func TestStatefulSessionIsInitialisedAndReused(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateful, SessionOptions{})
	ctx := context.Background()
	cs := r.connect(ctx)
	if cs.ID() == "" {
		t.Fatal("a stateful server answered initialise without a session id")
	}
	for range 3 {
		if _, err := cs.ListTools(ctx, nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := r.e.Sessions(); n != 1 {
		t.Errorf("sessions after three requests on one = %d, want 1", n)
	}
	// The same session, reached with a raw request, is still the one the
	// table holds.
	if code, _ := r.post(ctx, cs.ID(), toolsList); code != http.StatusOK {
		t.Errorf("tools/list on the session = %d, want 200", code)
	}
	// Closing the client ends the session (DELETE), and the table lets it go.
	if err := cs.Close(); err != nil {
		t.Fatal(err)
	}
	if n := r.e.Sessions(); n != 0 {
		t.Errorf("sessions after the client closed = %d, want 0", n)
	}
}

func TestStatefulUnknownSessionIs404(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateful, SessionOptions{})
	ctx := context.Background()
	cs := r.connect(ctx)

	if code, _ := r.post(ctx, "never-issued", toolsList); code != http.StatusNotFound {
		t.Errorf("an unknown session = %d, want 404", code)
	}
	// A session is its caller's, and its credential's: another user, or
	// the same user on another key or another OAuth client, presenting its
	// id is told it does not exist, not that it belongs to someone else.
	for name, other := range map[string]*authz.Principal{
		"another user":         user("u_2", "org_bench", "k_1"),
		"another key":          user("u_1", "org_bench", "k_2"),
		"an OAuth client":      {Kind: authz.KindUser, ID: "u_1", OrgID: "org_bench", AuthMethod: "oauth_at", ClientID: "client_a"},
		"another organisation": user("u_1", "org_other", "k_1"),
	} {
		r.caller.Store(other)
		if code, _ := r.post(ctx, cs.ID(), toolsList); code != http.StatusNotFound {
			t.Errorf("the session presented by %s = %d, want 404", name, code)
		}
	}
	// And it is its server's.
	r.caller.Store(user("u_1", "org_bench", "k_1"))
	r.s.server = &mcpserver.Server{ID: "srv_other", OrgID: "org_bench", Enabled: true, Sessions: mcpserver.SessionsStateful}
	if code, _ := r.post(ctx, cs.ID(), toolsList); code != http.StatusNotFound {
		t.Errorf("a session presented on another server = %d, want 404", code)
	}
	// Without a session, anything but initialise is a bad request.
	if code, _ := r.post(ctx, "", toolsList); code != http.StatusBadRequest {
		t.Errorf("tools/list without a session = %d, want 400", code)
	}
}

func TestStatefulIdleSessionIsClosed(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateful, SessionOptions{Idle: 10 * time.Minute})
	ctx := context.Background()
	idle := r.connect(ctx)
	busy := r.connect(ctx)

	r.clock.advance(9 * time.Minute)
	if _, err := busy.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
	r.clock.advance(2 * time.Minute)
	r.e.sessions.sweep()

	if n := r.e.Sessions(); n != 1 {
		t.Fatalf("sessions after the sweep = %d, want the one used recently", n)
	}
	if code, _ := r.post(ctx, idle.ID(), toolsList); code != http.StatusNotFound {
		t.Errorf("the idle session = %d, want 404", code)
	}
	if _, err := busy.ListTools(ctx, nil); err != nil {
		t.Errorf("the session in use was closed too: %v", err)
	}
}

func TestStatefulDrainClosesEverySession(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateful, SessionOptions{})
	ctx := context.Background()
	a := r.connect(ctx)
	b := r.connect(ctx)

	r.e.Close()

	if n := r.e.Sessions(); n != 0 {
		t.Errorf("sessions after drain = %d, want 0", n)
	}
	for _, cs := range []*sdk.ClientSession{a, b} {
		if code, _ := r.post(ctx, cs.ID(), toolsList); code != http.StatusNotFound {
			t.Errorf("a drained session = %d, want 404", code)
		}
	}
	if _, err := r.tryConnect(ctx); err == nil {
		t.Error("a draining endpoint opened a new session")
	}
}

// A stateless server keeps nothing, whatever the client sends.
func TestStatelessServerKeepsNoSession(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateless, SessionOptions{})
	ctx := context.Background()
	cs := r.connect(ctx)
	if cs.ID() != "" {
		t.Errorf("a stateless server issued session %q", cs.ID())
	}
	if got := whoami(t, ctx, cs); got != "u_1/" {
		t.Errorf("whoami = %q", got)
	}
	if n := r.e.Sessions(); n != 0 {
		t.Errorf("sessions = %d, want 0", n)
	}
	// A session id is ignored rather than refused, as before.
	code, h := r.post(ctx, "made-up", toolsList)
	if code != http.StatusOK || h.Get(sessionHeader) != "" {
		t.Errorf("stateless request with a session id = %d, session header %q; want 200 and none", code, h.Get(sessionHeader))
	}
}

// A session opened by one request runs every later one as that later
// request's caller: the same credential with narrower scopes is what the
// permission check reads, not the scopes it opened with.
func TestStatefulSessionRunsEachRequestAsItsOwnCaller(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateful, SessionOptions{})
	ctx := context.Background()
	wide := user("u_1", "org_bench", "k_1")
	wide.Scopes = []string{"mcp:tools:invoke", "mcp:tools:read"}
	r.caller.Store(wide)
	cs := r.connect(ctx)
	if got := whoami(t, ctx, cs); got != "u_1/mcp:tools:invoke,mcp:tools:read" {
		t.Fatalf("first call ran as %q", got)
	}
	narrow := user("u_1", "org_bench", "k_1")
	narrow.Scopes = []string{"mcp:tools:invoke"}
	r.caller.Store(narrow)
	if got := whoami(t, ctx, cs); got != "u_1/mcp:tools:invoke" {
		t.Errorf("a call on the narrower credential ran as %q", got)
	}
}

// Once bound to a request, a handler reads nothing of the session's
// context but the SDK's own keys.
func TestBoundContextReadsNothingOfTheOpener(t *testing.T) {
	t.Parallel()
	type key struct{}
	opener := authz.WithPrincipal(context.WithValue(context.Background(), key{}, "opener"), user("u_opener", "org", "k"))
	bound, cancel := bindTo(opener, context.Background())
	defer cancel()
	if v := bound.Value(key{}); v != nil {
		t.Errorf("a key the request does not carry read the opener's value %v", v)
	}
	if p, _ := authz.From(bound); p != nil {
		t.Errorf("the request carries no caller, and the handler saw the opener, %s", p.ID)
	}
}

// A request's deadline, the router's timeout in production, stops a call
// running on a stateful session.
func TestStatefulCallStopsAtTheRequestDeadline(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateful, SessionOptions{})
	ctx := context.Background()
	cs := r.connect(ctx)
	r.deadline.Store(int64(200 * time.Millisecond))
	go func() { _, _ = cs.CallTool(ctx, &sdk.CallToolParams{Name: "hold"}) }()
	<-r.holding
	select {
	case err := <-r.stopped:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("the call stopped with %v, want the request's deadline", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the call ran on past its request's deadline")
	}
}

// tools/list on an open session shows what the current request may see,
// not what the session was opened with.
func TestStatefulToolsListFollowsTheRequest(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateful, SessionOptions{})
	ctx := context.Background()
	cs := r.connect(ctx)
	before, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	revoked := before.Tools[0].Name
	fewer := map[string]bool{}
	for k, v := range r.s.names {
		fewer[k] = v
	}
	delete(fewer, revoked)
	r.names.Store(&fewer)
	after, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Tools) != len(before.Tools)-1 {
		t.Errorf("tools/list after a tool was taken away lists %d, want %d", len(after.Tools), len(before.Tools)-1)
	}
	for _, tl := range after.Tools {
		if tl.Name == revoked {
			t.Errorf("%s is still listed on the open session", revoked)
		}
	}
	if _, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: revoked}); err == nil {
		t.Errorf("%s can still be called on the open session", revoked)
	}
}

// A session lasts no longer than the maximum age, however busy.
func TestStatefulSessionHasAMaximumAge(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateful, SessionOptions{Idle: time.Hour, MaxAge: 2 * time.Hour})
	ctx := context.Background()
	cs := r.connect(ctx)
	for range 3 {
		r.clock.advance(50 * time.Minute)
		if code, _ := r.post(ctx, cs.ID(), toolsList); code != http.StatusOK && r.clock.Now().Sub(time.Unix(1_700_000_000, 0)) < 2*time.Hour {
			t.Fatalf("a session in use inside its age = %d", code)
		}
	}
	if code, _ := r.post(ctx, cs.ID(), toolsList); code != http.StatusNotFound {
		t.Errorf("a session past its maximum age = %d, want 404", code)
	}
	if n := r.e.Sessions(); n != 0 {
		t.Errorf("sessions after the maximum age = %d, want 0", n)
	}
}

// A caller at its own limit makes room by closing its own session idle
// longest, and nobody else's.
func TestCallerAtItsCapDisplacesOnlyItself(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateful, SessionOptions{Max: 100, PerCaller: 2, PerOrg: 100})
	ctx := context.Background()
	r.caller.Store(user("u_b", "org_bench", "k_b"))
	bystander := r.connect(ctx)
	r.caller.Store(user("u_a", "org_bench", "k_a"))
	first := r.connect(ctx)
	r.clock.advance(time.Second)
	second := r.connect(ctx)
	r.clock.advance(time.Second)
	r.clock.advance(time.Hour) // the bystander is the idlest session of all
	third := r.connect(ctx)

	if code, _ := r.post(ctx, first.ID(), toolsList); code != http.StatusNotFound {
		t.Errorf("the caller's own oldest session = %d, want 404 once it made room", code)
	}
	for name, cs := range map[string]*sdk.ClientSession{"second": second, "third": third} {
		if code, _ := r.post(ctx, cs.ID(), toolsList); code != http.StatusOK {
			t.Errorf("the caller's %s session = %d, want 200", name, code)
		}
	}
	r.caller.Store(user("u_b", "org_bench", "k_b"))
	if code, _ := r.post(ctx, bystander.ID(), toolsList); code != http.StatusOK {
		t.Errorf("another caller's idle session = %d, want 200: it was closed to make room", code)
	}

	// With every one of its sessions busy, the caller is refused rather
	// than allowed to make room elsewhere.
	r.caller.Store(user("u_a", "org_bench", "k_a"))
	busy := r.newCaller(ctx, 2)
	code, h := r.post(ctx, "", initialize)
	if code != http.StatusTooManyRequests || h.Get("Retry-After") == "" {
		t.Errorf("initialise at the caller's limit with every session busy = %d, want 429 with Retry-After", code)
	}
	busy()
}

// One tenant filling the replica closes its own sessions to make room,
// not another tenant's; once none of its own is idle, it is refused.
func TestOneTenantFillingTheTableKeepsAnothersSessions(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateful, SessionOptions{Max: 4, PerCaller: 16, PerOrg: 16})
	ctx := context.Background()
	r.caller.Store(user("u_b", "org_b", "k_b"))
	tenantB := r.connect(ctx)
	r.clock.advance(time.Hour) // B's session is the idlest there is

	r.caller.Store(user("u_a", "org_a", "k_a"))
	for range 8 {
		r.connect(ctx)
		r.clock.advance(time.Second)
	}
	if n := r.e.Sessions(); n != 4 {
		t.Errorf("sessions = %d, want the limit of 4", n)
	}
	r.caller.Store(user("u_b", "org_b", "k_b"))
	if code, _ := r.post(ctx, tenantB.ID(), toolsList); code != http.StatusOK {
		t.Fatalf("tenant B's session = %d after tenant A filled the table, want 200", code)
	}

	// Tenant B still has room to open another, at A's expense: A holds
	// more than its share.
	r.connect(ctx)
	r.caller.Store(user("u_b", "org_b", "k_b"))
	if code, _ := r.post(ctx, tenantB.ID(), toolsList); code != http.StatusOK {
		t.Errorf("tenant B's first session = %d after it opened a second", code)
	}
}

// A replica full of busy sessions refuses a newcomer with 503.
func TestStatefulFullOfBusySessionsRefuses(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateful, SessionOptions{Max: 1, PerCaller: 16, PerOrg: 16})
	ctx := context.Background()
	done := r.newCaller(ctx, 1)
	r.caller.Store(user("u_b", "org_b", "k_b"))
	code, h := r.post(ctx, "", initialize)
	if code != http.StatusServiceUnavailable || h.Get("Retry-After") == "" {
		t.Errorf("initialise with every place busy = %d (Retry-After %q), want 503 with Retry-After", code, h.Get("Retry-After"))
	}
	done()
}

const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`

// newCaller opens n sessions as the current caller and keeps each busy in
// a held call; the function it returns lets them all go.
func (r *rig) newCaller(ctx context.Context, n int) func() {
	r.t.Helper()
	var calls sync.WaitGroup
	for range n {
		cs := r.connect(ctx)
		calls.Go(func() { _, _ = cs.CallTool(ctx, &sdk.CallToolParams{Name: "hold"}) })
		<-r.holding
	}
	return func() {
		close(r.release)
		calls.Wait()
	}
}
