package mcp

import (
	"context"
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
	clock  *fakeClock
	// release lets a call to the "hold" tool return.
	release chan struct{}
	holding chan struct{}
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
		release: make(chan struct{}), holding: make(chan struct{}, 8)}
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
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: p.ID + "/" + p.AuthMethod}}}, nil
		})
	r.s.mcp.AddTool(&sdk.Tool{Name: "hold", InputSchema: map[string]any{"type": "object"}},
		func(ctx context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			r.holding <- struct{}{}
			select {
			case <-r.release:
			case <-ctx.Done():
			}
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "released"}}}, nil
		})
	r.caller.Store(&authz.Principal{Kind: authz.KindUser, ID: "u_1", OrgID: "org_bench", AuthMethod: "api_key"})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// What serve does once buildSurface has succeeded: a surface of
		// the request's own, sharing the assembled server.
		ctx := authz.WithPrincipal(req.Context(), r.caller.Load())
		s := &surface{server: r.s.server, names: r.s.names, byName: r.s.byName, mcp: r.s.mcp}
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
	// A session is its caller's: another user presenting its id is told
	// it does not exist, not that it belongs to someone else.
	r.caller.Store(&authz.Principal{Kind: authz.KindUser, ID: "u_2", OrgID: "org_bench", AuthMethod: "api_key"})
	if code, _ := r.post(ctx, cs.ID(), toolsList); code != http.StatusNotFound {
		t.Errorf("another caller's session = %d, want 404", code)
	}
	// And it is its server's.
	r.caller.Store(&authz.Principal{Kind: authz.KindUser, ID: "u_1", OrgID: "org_bench", AuthMethod: "api_key"})
	r.s.server = &mcpserver.Server{ID: "srv_other", OrgID: "org_bench", Enabled: true, Sessions: mcpserver.SessionsStateful}
	if code, _ := r.post(ctx, cs.ID(), toolsList); code != http.StatusNotFound {
		t.Errorf("a session presented on another server = %d, want 404", code)
	}
	// Without a session, anything but initialise is a bad request.
	if code, _ := r.post(ctx, "", toolsList); code != http.StatusBadRequest {
		t.Errorf("tools/list without a session = %d, want 400", code)
	}
}

// A session opened by one request runs every later one as that later
// request's caller: a credential exchanged mid-session is the one the
// permission check reads.
func TestStatefulSessionRunsEachRequestAsItsOwnCaller(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateful, SessionOptions{})
	ctx := context.Background()
	cs := r.connect(ctx)
	if got := whoami(t, ctx, cs); got != "u_1/api_key" {
		t.Fatalf("first call ran as %q", got)
	}
	r.caller.Store(&authz.Principal{Kind: authz.KindUser, ID: "u_1", OrgID: "org_bench", AuthMethod: "oauth"})
	if got := whoami(t, ctx, cs); got != "u_1/oauth" {
		t.Errorf("a call on a refreshed credential ran as %q, want u_1/oauth", got)
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

func TestStatefulFullTableMakesRoom(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateful, SessionOptions{Max: 2})
	ctx := context.Background()
	oldest := r.connect(ctx)
	r.clock.advance(time.Second)
	newer := r.connect(ctx)
	r.clock.advance(time.Second)
	third := r.connect(ctx)

	if n := r.e.Sessions(); n != 2 {
		t.Errorf("sessions = %d, want the limit of 2", n)
	}
	if code, _ := r.post(ctx, oldest.ID(), toolsList); code != http.StatusNotFound {
		t.Errorf("the session idle longest = %d, want 404 once it made room", code)
	}
	for _, cs := range []*sdk.ClientSession{newer, third} {
		if _, err := cs.ListTools(ctx, nil); err != nil {
			t.Errorf("a session that should have been kept: %v", err)
		}
	}
}

func TestStatefulFullOfBusySessionsRefuses(t *testing.T) {
	t.Parallel()
	r := newRig(t, mcpserver.SessionsStateful, SessionOptions{Max: 1})
	ctx := context.Background()
	cs := r.connect(ctx)
	done := make(chan error, 1)
	go func() {
		_, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "hold"})
		done <- err
	}()
	<-r.holding

	if _, err := r.tryConnect(ctx); err == nil {
		t.Error("a new session was opened while the only place was busy")
	}
	code, h := r.post(ctx, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`)
	if code != http.StatusServiceUnavailable || h.Get("Retry-After") == "" {
		t.Errorf("initialise with every place busy = %d (Retry-After %q), want 503 with Retry-After", code, h.Get("Retry-After"))
	}
	close(r.release)
	if err := <-done; err != nil {
		t.Errorf("the busy call: %v", err)
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
	if got := whoami(t, ctx, cs); got != "u_1/api_key" {
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
