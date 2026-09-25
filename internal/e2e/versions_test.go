package e2e

import (
	"net/http"
	"strconv"
	"testing"
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
