package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sync/errgroup"
)

// Every connector and server write that takes expectedVersion refuses a
// stale one with the tool editor's 409, carrying the version stored now,
// and moves the version by exactly one when it goes through.
//
// Not parallel: each case starts a server that migrates the shared
// database on the way up.
func TestConnectorAndServerVersionConflicts(t *testing.T) {
	type route struct {
		name string
		// version reads the version of the thing the route writes.
		version func(f *toolFixture, t *testing.T) int64
		// write sends the guarded request with expectedVersion v and
		// returns the status and the version the reply carries.
		write func(t *testing.T, f *toolFixture, v int64, e *apiError) (int, int64)
	}

	patchConnector := func(body map[string]any) func(*testing.T, *toolFixture, int64, *apiError) (int, int64) {
		return func(t *testing.T, f *toolFixture, v int64, e *apiError) (int, int64) {
			return f.writeVersioned(t, http.MethodPatch, "/api/v1/connectors/"+f.conn.ID, body, v, e)
		}
	}
	patchServer := func(body map[string]any) func(*testing.T, *toolFixture, int64, *apiError) (int, int64) {
		return func(t *testing.T, f *toolFixture, v int64, e *apiError) (int, int64) {
			return f.writeVersioned(t, http.MethodPatch, "/api/v1/servers/"+f.srv.ID, body, v, e)
		}
	}
	restore := func(kind string) func(*testing.T, *toolFixture, int64, *apiError) (int, int64) {
		return func(t *testing.T, f *toolFixture, v int64, e *apiError) (int, int64) {
			id := f.conn.ID
			if kind == "servers" {
				id = f.srv.ID
			}
			first := f.oldestRevision(t, kind, id)
			path := "/api/v1/" + kind + "/" + id + "/revisions/" + strconv.Itoa(first) + "/restore"
			return f.writeVersioned(t, http.MethodPost, path, map[string]any{}, v, e)
		}
	}

	routes := []route{
		{"connector update", (*toolFixture).connectorVersion, patchConnector(map[string]any{"name": "Renamed"})},
		{"connector disable", (*toolFixture).connectorVersion, patchConnector(map[string]any{"enabled": false})},
		{"connector credentials", (*toolFixture).connectorVersion, func(t *testing.T, f *toolFixture, v int64, e *apiError) (int, int64) {
			return f.writeVersioned(t, http.MethodPut, "/api/v1/connectors/"+f.conn.ID+"/credentials",
				map[string]any{"credentials": map[string]string{"FAKE_KEY": "rotated"}}, v, e)
		}},
		{"connector restore", (*toolFixture).connectorVersion, restore("connectors")},
		{"server update", (*toolFixture).apiServerVersion, patchServer(map[string]any{"name": "Renamed server"})},
		{"server disable", (*toolFixture).apiServerVersion, patchServer(map[string]any{"enabled": false})},
		{"server connectors", (*toolFixture).apiServerVersion, func(t *testing.T, f *toolFixture, v int64, e *apiError) (int, int64) {
			return f.writeVersioned(t, http.MethodPatch, "/api/v1/servers/"+f.srv.ID,
				map[string]any{"connectorIds": []string{}}, v, e)
		}},
		{"server restore", (*toolFixture).apiServerVersion, restore("servers")},
	}

	for _, r := range routes {
		t.Run(r.name, func(t *testing.T) {
			f := newToolFixture(t)
			// A change made by someone else, without a version: the field is
			// optional for one release. Renaming both leaves a revision to
			// restore to, too.
			read := r.version(f, t)
			f.rename(t)
			current := r.version(f, t)
			if current == read {
				t.Fatalf("the rename did not move the version (%d)", read)
			}

			var e apiError
			code, _ := r.write(t, f, read, &e)
			if code != http.StatusConflict || !e.hasCode("version_conflict") {
				t.Fatalf("a write against version %d when %d is stored: %d %v, want 409 version_conflict", read, current, code, e.codes())
			}
			if got, ok := e.currentVersion(); !ok || got != current {
				t.Errorf("the 409 says the stored version is %v (found %v), want %d", got, ok, current)
			}
			if after := r.version(f, t); after != current {
				t.Errorf("a refused write moved the version from %d to %d", current, after)
			}

			code, written := r.write(t, f, current, &apiError{})
			if code != http.StatusOK {
				t.Fatalf("a write against the stored version %d: %d, want 200", current, code)
			}
			if written != current+1 {
				t.Errorf("the reply carries version %d, want %d", written, current+1)
			}
		})
	}
}

// A tool edit's 409 carries the version stored now as well: tools,
// connectors and servers share the check and the reply.
func TestToolVersionConflictCarriesCurrentVersion(t *testing.T) {
	f := newToolFixture(t)
	tl := f.importedTool(t)
	if code := putTool(t, f.h, tl.ID, tl.Definition, tl.Version, nil); code != 200 {
		t.Fatalf("first edit: %d", code)
	}
	now := f.getTool(t, tl.ID).Version
	var e apiError
	if code := putTool(t, f.h, tl.ID, tl.Definition, tl.Version, &e); code != http.StatusConflict || !e.hasCode("version_conflict") {
		t.Fatalf("a stale edit: %d %v, want 409 version_conflict", code, e.codes())
	}
	if got, ok := e.currentVersion(); !ok || got != now {
		t.Errorf("the 409 says the stored version is %v (found %v), want %d", got, ok, now)
	}
}

// currentVersion is the version a version_conflict reply says is stored.
func (e apiError) currentVersion() (int64, bool) {
	for _, d := range e.Errors {
		if d.Location != "version" {
			continue
		}
		n, ok := d.Value.(float64)
		return int64(n), ok
	}
	return 0, false
}

// writeVersioned sends body with expectedVersion v and returns the status
// and the version of the connector or server in the reply.
func (f *toolFixture) writeVersioned(t *testing.T, method, path string, body map[string]any, v int64, e *apiError) (int, int64) {
	t.Helper()
	b := map[string]any{"expectedVersion": v}
	for k, val := range body {
		b[k] = val
	}
	var out struct {
		apiError
		Version int64 `json:"version"`
	}
	code := f.h.do(t, method, path, b, &out)
	*e = out.apiError
	return code, out.Version
}

// rename changes the connector's and the server's name without saying
// which version it read.
func (f *toolFixture) rename(t *testing.T) {
	t.Helper()
	if code := f.h.do(t, http.MethodPatch, "/api/v1/connectors/"+f.conn.ID, map[string]any{"name": "Changed elsewhere"}, nil); code != 200 {
		t.Fatalf("rename the connector: %d", code)
	}
	if code := f.h.do(t, http.MethodPatch, "/api/v1/servers/"+f.srv.ID, map[string]any{"name": "Changed elsewhere"}, nil); code != 200 {
		t.Fatalf("rename the server: %d", code)
	}
}

func (f *toolFixture) connectorVersion(t *testing.T) int64 {
	t.Helper()
	var c struct {
		Version int64 `json:"version"`
	}
	if code := f.h.do(t, http.MethodGet, "/api/v1/connectors/"+f.conn.ID, nil, &c); code != 200 {
		t.Fatalf("get connector: %d", code)
	}
	return c.Version
}

func (f *toolFixture) apiServerVersion(t *testing.T) int64 {
	t.Helper()
	var s struct {
		Version int64 `json:"version"`
	}
	if code := f.h.do(t, http.MethodGet, "/api/v1/servers/"+f.srv.ID, nil, &s); code != 200 {
		t.Fatalf("get server: %d", code)
	}
	return s.Version
}

// oldestRevision is the first revision recorded for a connector or server.
func (f *toolFixture) oldestRevision(t *testing.T, kind, id string) int {
	t.Helper()
	var revs revisionList
	if code := f.h.do(t, http.MethodGet, "/api/v1/"+kind+"/"+id+"/revisions", nil, &revs); code != 200 || len(revs.Revisions) == 0 {
		t.Fatalf("%s revisions: %d, %d revisions", kind, code, len(revs.Revisions))
	}
	return revs.Revisions[len(revs.Revisions)-1].Revision
}

// Two writes against the same version, sent at once, cannot both go
// through: the version is compared under the connector's row lock in the
// transaction that writes, so the second one to take the lock sees the
// first one's version.
func TestConcurrentConnectorWritesOneWins(t *testing.T) {
	f := newToolFixture(t)
	read := f.connectorVersion(t)
	path := "/api/v1/connectors/" + f.conn.ID

	var ok, conflict atomic.Int32
	g, ctx := errgroup.WithContext(context.Background())
	for i := range 2 {
		g.Go(func() error {
			body := map[string]any{"name": fmt.Sprintf("Writer %d", i), "expectedVersion": read}
			code, err := f.h.send(ctx, http.MethodPatch, path, body)
			switch {
			case err != nil:
				return err
			case code == http.StatusOK:
				ok.Add(1)
			case code == http.StatusConflict:
				conflict.Add(1)
			default:
				return fmt.Errorf("writer %d: status %d", i, code)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}
	if ok.Load() != 1 || conflict.Load() != 1 {
		t.Errorf("two writes against version %d: %d went through and %d were refused, want 1 and 1", read, ok.Load(), conflict.Load())
	}
	if now := f.connectorVersion(t); now != read+1 {
		t.Errorf("the version is %d after one write from %d, want %d", now, read, read+1)
	}
}

// Disabling a connector takes its tools off the MCP endpoint at once, not
// when the cached tool list runs out: the write moves the version of
// every server the connector is on, which is what the list is cached
// under. A call was already checked against live state; the list was not.
func TestDisabledConnectorIsRefusedAtOnce(t *testing.T) {
	f := newToolFixture(t)
	tl := f.importedTool(t)
	if res, err := f.tryMCP(tl.Name); err != nil || res.IsError {
		t.Fatalf("a call before the connector is disabled: %v %+v", err, res)
	}
	if _, ok := f.mcpTools(t)[tl.Name]; !ok {
		t.Fatalf("%s is not listed before the connector is disabled", tl.Name)
	}
	if code := f.h.do(t, http.MethodPatch, "/api/v1/connectors/"+f.conn.ID, map[string]any{"enabled": false}, nil); code != 200 {
		t.Fatalf("disable the connector: %d", code)
	}
	if res, err := f.tryMCP(tl.Name); err == nil && !res.IsError {
		t.Errorf("a disabled connector's tool %s was still called: %+v", tl.Name, res)
	}
	if _, ok := f.mcpTools(t)[tl.Name]; ok {
		t.Errorf("a disabled connector's tool %s is still listed", tl.Name)
	}
}

// tryMCP calls a tool and returns what came back, a refusal included.
func (f *toolFixture) tryMCP(tool string) (*sdk.CallToolResult, error) {
	ctx := context.Background()
	transport := &sdk.StreamableClientTransport{
		Endpoint:   f.h.url + "/mcp/" + f.srv.ID,
		HTTPClient: &http.Client{Transport: &keyRoundTripper{key: f.key, base: f.h.client.Transport}},
	}
	sess, err := sdk.NewClient(&sdk.Implementation{Name: "versions-e2e", Version: "1"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = sess.Close() }()
	return sess.CallTool(ctx, &sdk.CallToolParams{Name: tool, Arguments: map[string]any{"id": "1"}})
}

// send is do for use off the test goroutine: it reports failures instead
// of stopping the test, and leaves the session cookie alone.
func (h *harness) send(ctx context.Context, method, path string, body any) (int, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, method, h.url+path, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", h.cookie)
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}
