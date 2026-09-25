package e2e

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type serverWire struct {
	ID       string `json:"id"`
	Sessions string `json:"sessions"`
	Version  int64  `json:"version"`
}

// connectMCP opens a client session on the fixture's server with its key.
func (f *toolFixture) connectMCP(t *testing.T, client *sdk.Client) *sdk.ClientSession {
	t.Helper()
	transport := &sdk.StreamableClientTransport{
		Endpoint:             f.h.url + "/mcp/" + f.srv.ID,
		HTTPClient:           &http.Client{Transport: &keyRoundTripper{key: f.key, base: f.h.client.Transport}},
		DisableStandaloneSSE: true,
	}
	if client == nil {
		client = sdk.NewClient(&sdk.Implementation{Name: "sessions-e2e", Version: "1"}, nil)
	}
	sess, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

// setSessions switches the fixture's server between the two modes over
// the API, as the server screen does.
func (f *toolFixture) setSessions(t *testing.T, mode string) serverWire {
	t.Helper()
	var cur serverWire
	if code := f.h.do(t, http.MethodGet, "/api/v1/servers/"+f.srv.ID, nil, &cur); code != 200 {
		t.Fatalf("get server: %d", code)
	}
	var out serverWire
	if code := f.h.do(t, http.MethodPatch, "/api/v1/servers/"+f.srv.ID,
		map[string]any{"sessions": mode, "expectedVersion": cur.Version}, &out); code != 200 {
		t.Fatalf("set sessions %s: %d", mode, code)
	}
	return out
}

// The setting is on the API, kept in the revision history, and decides
// whether the endpoint issues a session.
func TestServerSessionsSetting(t *testing.T) {
	f := newToolFixture(t)
	ctx := context.Background()

	var created serverWire
	if code := f.h.do(t, http.MethodGet, "/api/v1/servers/"+f.srv.ID, nil, &created); code != 200 || created.Sessions != "stateless" {
		t.Fatalf("a new server: %d sessions=%q, want stateless", code, created.Sessions)
	}
	if sess := f.connectMCP(t, nil); sess.ID() != "" {
		t.Errorf("a stateless server issued session %q", sess.ID())
	}

	var e apiError
	if code := f.h.do(t, http.MethodPatch, "/api/v1/servers/"+f.srv.ID, map[string]any{"sessions": "sticky"}, &e); code != http.StatusUnprocessableEntity {
		t.Errorf("an unknown mode: %d, want 422", code)
	}

	if got := f.setSessions(t, "stateful"); got.Sessions != "stateful" || got.Version != created.Version+1 {
		t.Fatalf("after switching: %+v", got)
	}
	sess := f.connectMCP(t, nil)
	if sess.ID() == "" {
		t.Fatal("a stateful server answered initialise without a session")
	}
	for i := range 2 {
		res, err := sess.CallTool(ctx, &sdk.CallToolParams{Name: "fake_get_item", Arguments: map[string]any{"id": strconv.Itoa(i)}})
		if err != nil || res.IsError {
			t.Fatalf("call %d on the session: %v %+v", i, err, res)
		}
	}
	if *f.calls != 2 {
		t.Errorf("upstream calls = %d, want 2", *f.calls)
	}
	if n := f.h.deps.MCP.Sessions(); n < 1 {
		t.Errorf("the endpoint holds %d sessions", n)
	}

	// An id this replica never issued is unknown: the client is told to
	// initialise again.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, f.h.url+"/mcp/"+f.srv.ID,
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("X-API-Key", f.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", "not-a-session")
	resp, err := f.h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("an unknown session: %d, want 404", resp.StatusCode)
	}

	// The change is a revision, and restoring the one before it puts the
	// server back to stateless.
	var revs revisionList
	if code := f.h.do(t, http.MethodGet, "/api/v1/servers/"+f.srv.ID+"/revisions", nil, &revs); code != 200 || len(revs.Revisions) < 2 {
		t.Fatalf("server revisions: %d %+v", code, revs)
	}
	first := revs.Revisions[len(revs.Revisions)-1].Revision
	var restored serverWire
	if code := f.h.do(t, http.MethodPost, "/api/v1/servers/"+f.srv.ID+"/revisions/"+strconv.Itoa(first)+"/restore", nil, &restored); code != 200 {
		t.Fatalf("restore: %d", code)
	}
	if restored.Sessions != "stateless" {
		t.Errorf("restoring the first revision left sessions %q, want stateless", restored.Sessions)
	}
}
