package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/catalog"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

type resyncPlan struct {
	BundledHash string `json:"bundledHash"`
	Outdated    bool   `json:"outdated"`
	Version     int64  `json:"version"`
	Update      []struct {
		Name    string   `json:"name"`
		Changed []string `json:"changed"`
	} `json:"update"`
	Add        []struct{ Name string }  `json:"add"`
	Remove     []struct{ Name string }  `json:"remove"`
	NotApplied []struct{ Field string } `json:"notApplied"`
}

type connectorView struct {
	ID              string `json:"id"`
	CatalogOutdated bool   `json:"catalogOutdated"`
	CatalogHash     string `json:"catalogHash"`
	Version         int64  `json:"version"`
	ReadOnly        bool   `json:"readOnly"`
}

// ghostV120 is the content hash ghost had in the v1.2.0 catalog, which
// the embedded index keeps as its history.
const ghostV120 = "3c1810cf8960"

func (h *harness) bypass(t *testing.T, stmts ...func(ctx context.Context, tx pgx.Tx) error) {
	t.Helper()
	ctx := context.Background()
	if err := h.db.Bypass(ctx, "e2e resync", func(tx pgx.Tx) error {
		for _, s := range stmts {
			if err := s(ctx, tx); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func execSQL(q string, args ...any) func(ctx context.Context, tx pgx.Tx) error {
	return func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, q, args...)
		return err
	}
}

// TestCatalogResync installs a catalog adapter, makes the installed copy
// look like the one v1.2.0 installed, and re-syncs it through the API.
func TestCatalogResync(t *testing.T) {
	f := newToolFixture(t)
	h := f.h
	const tool = "ghost_list_posts"

	var installed connectorView
	if code := h.do(t, http.MethodPost, "/api/v1/connectors/install", map[string]any{"slug": "ghost",
		"credentials": map[string]string{"GHOST_ADMIN_API_URL": f.upstream, "GHOST_ADMIN_JWT": "not-a-real-token"}}, &installed); code != 200 {
		t.Fatalf("install: %d", code)
	}
	// Two more installs: one from a catalog this server does not know,
	// possibly a newer one, which must be neither outdated nor re-synced.
	var unknown connectorView
	if code := h.do(t, http.MethodPost, "/api/v1/connectors/install", map[string]any{"slug": "ghost",
		"credentials": map[string]string{"GHOST_ADMIN_API_URL": f.upstream, "GHOST_ADMIN_JWT": "not-a-real-token"}}, &unknown); code != 200 {
		t.Fatalf("install: %d", code)
	}
	// v1.2.0 installed it: its hash and one tool's text differ from what
	// this binary carries. Only an upgrade produces that state.
	h.bypass(t,
		execSQL(`UPDATE connectors SET catalog_hash = $2 WHERE id = $1`, installed.ID, ghostV120),
		execSQL(`UPDATE connectors SET catalog_hash = 'fromthefuture' WHERE id = $1`, unknown.ID),
		execSQL(`UPDATE tools SET definition = jsonb_set(definition, '{description}', '"The older description."')
			WHERE connector_id = $1 AND name = $2`, installed.ID, tool),
		execSQL(`INSERT INTO mcp_server_connectors (server_id, connector_id, organization_id) VALUES ($1, $2, $3)`,
			f.srv.ID, installed.ID, f.admin.Org.ID),
	)

	var list []connectorView
	if code := h.do(t, http.MethodGet, "/api/v1/connectors", nil, &list); code != 200 {
		t.Fatalf("list: %d", code)
	}
	outdated := map[string]bool{}
	for _, c := range list {
		outdated[c.ID] = c.CatalogOutdated
	}
	if !outdated[installed.ID] || outdated[unknown.ID] || outdated[f.conn.ID] {
		t.Fatalf("catalogOutdated = %v; want only %s", outdated, installed.ID)
	}

	var plan resyncPlan
	if code := h.do(t, http.MethodGet, "/api/v1/connectors/"+installed.ID+"/resync", nil, &plan); code != 200 {
		t.Fatalf("preview: %d", code)
	}
	var mcpToolName string
	for _, u := range plan.Update {
		if u.Name == tool && slices.Equal(u.Changed, []string{"description"}) {
			mcpToolName = u.Name
		}
	}
	if !plan.Outdated || mcpToolName == "" {
		t.Fatalf("preview = %+v", plan)
	}
	var e apiError
	for _, id := range []string{f.conn.ID, unknown.ID} {
		if code := h.do(t, http.MethodGet, "/api/v1/connectors/"+id+"/resync", nil, &e); code != http.StatusConflict {
			t.Errorf("preview of %s: %d %s, want 409", id, code, e.Detail)
		}
	}
	if code := h.do(t, http.MethodPost, "/api/v1/connectors/"+unknown.ID+"/resync",
		map[string]any{"catalogHash": plan.BundledHash, "expectedVersion": unknown.Version}, &e); code != http.StatusConflict {
		t.Errorf("re-sync of a connector from an unknown catalog: %d %s, want 409", code, e.Detail)
	}

	apply := map[string]any{"catalogHash": plan.BundledHash, "expectedVersion": plan.Version}

	// Re-syncing rewrites tools, so connectors:update alone is not enough.
	role := f.customRole(t, "connector-only", "connectors:read", "connectors:update", "tools:read")
	m := f.member(t, role, "org", "")
	if code := m.do(t, http.MethodPost, "/api/v1/connectors/"+installed.ID+"/resync", apply, nil); code != http.StatusForbidden {
		t.Errorf("re-sync without tools:update: %d, want 403", code)
	}

	e = apiError{}
	stale := map[string]any{"catalogHash": plan.BundledHash, "expectedVersion": plan.Version + 1}
	if code := h.do(t, http.MethodPost, "/api/v1/connectors/"+installed.ID+"/resync", stale, &e); code != http.StatusConflict || !e.hasCode("resync_stale") {
		t.Errorf("re-sync of a stale review: %d %+v, want 409 resync_stale", code, e)
	}

	var applied struct {
		Connector connectorView `json:"connector"`
		Applied   resyncPlan    `json:"applied"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/connectors/"+installed.ID+"/resync", apply, &applied); code != 200 {
		t.Fatalf("apply: %d", code)
	}
	if applied.Connector.CatalogOutdated || applied.Connector.Version != plan.Version+1 {
		t.Errorf("apply = %+v", applied)
	}
	if served := f.mcpTools(t)[tool]; served == nil || served.Description == "The older description." {
		t.Errorf("MCP clients are still served the old tool: %+v", served)
	}

	events := h.auditEvents(t, context.Background(), f.admin.Org.ID)
	if !slices.Contains(actions(events), "connector.resync") {
		t.Errorf("no connector.resync in the audit trail: %v", actions(events))
	}
}

// gateCatalog is a one-adapter catalog whose tool deletes, and says it
// does not: its explicit destructiveHint false is what the destructive
// gate is about. Its earlier version is "gate-v1".
func gateCatalog(t *testing.T, upstream string) *catalog.Catalog {
	t.Helper()
	doc := `apiVersion: supermcp.dev/v2
kind: Adapter
metadata:
  slug: gate
  name: Gate
  description: An adapter for the destructive gate test.
  region: intl
transport:
  type: http
  baseUrl: ` + upstream + `
auth:
  type: none
tools:
  - name: remove_item
    description: Removes one item; the adapter claims it is not destructive.
    input:
      type: object
      properties:
        id: {type: string}
    operation:
      method: DELETE
      path: /items/{{params.id}}
    annotations:
      destructiveHint: false
`
	a, err := adapter.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := adapter.ContentHash(a)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := json.Marshal(adapter.Index{Count: 1, CatalogHash: "gate", Adapters: []adapter.IndexEntry{{
		Slug: "gate", Name: "Gate", Region: "intl", Transport: adapter.TransportHTTP, Auth: a.Auth.Type,
		Keyless: true, ToolCount: 1, ContentHash: hash, PreviousHashes: []string{"gate-v1"}, Dir: "intl/gate",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.LoadFS(fstest.MapFS{
		"index.gen.json":                {Data: idx},
		"intl/gate/" + adapter.FileName: {Data: []byte(doc)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

// TestCatalogResyncDestructiveGate: a bundled tool that takes the
// destructive hint off a deleting operation needs tools:invoke:destructive,
// decided on the connector as it is when the re-sync is written, and a
// review older than the connector is refused.
func TestCatalogResyncDestructiveGate(t *testing.T) {
	upstream, _ := fakeUpstream(t)
	f := newToolFixtureWith(t, harnessOptions{catalog: gateCatalog(t, upstream.URL)})
	h := f.h

	var c connectorView
	if code := h.do(t, http.MethodPost, "/api/v1/connectors/install", map[string]any{"slug": "gate"}, &c); code != 200 {
		t.Fatalf("install: %d", code)
	}
	// The earlier version said nothing about the hint.
	h.bypass(t,
		execSQL(`UPDATE connectors SET catalog_hash = 'gate-v1' WHERE id = $1`, c.ID),
		execSQL(`UPDATE tools SET definition = definition - 'annotations' WHERE connector_id = $1`, c.ID),
	)
	var plan resyncPlan
	if code := h.do(t, http.MethodGet, "/api/v1/connectors/"+c.ID+"/resync", nil, &plan); code != 200 {
		t.Fatalf("preview: %d", code)
	}
	if len(plan.Update) != 1 || !slices.Equal(plan.Update[0].Changed, []string{"annotations"}) {
		t.Fatalf("preview = %+v", plan)
	}

	// The editor role has connectors:update and tools:update but not
	// tools:invoke:destructive.
	editor := f.member(t, "role_editor", "org", "")
	resync := func(who *harness, version int64, out any) int {
		return who.do(t, http.MethodPost, "/api/v1/connectors/"+c.ID+"/resync",
			map[string]any{"catalogHash": plan.BundledHash, "expectedVersion": version}, out)
	}

	// A caller naming the version a concurrent edit is about to produce
	// is refused: what it reviewed is not what is there.
	var e apiError
	if code := resync(editor, plan.Version+1, &e); code != http.StatusConflict || !e.hasCode("resync_stale") {
		t.Errorf("re-sync naming a version not yet reached: %d %+v, want 409 resync_stale", code, e)
	}
	writable := false
	var flipped connectorView
	if code := h.do(t, http.MethodPatch, "/api/v1/connectors/"+c.ID, map[string]any{"readOnly": writable}, &flipped); code != 200 || flipped.ReadOnly {
		t.Fatalf("make the connector writable: %d %+v", code, flipped)
	}
	if code := resync(editor, flipped.Version, nil); code != http.StatusForbidden {
		t.Errorf("declassifying re-sync without tools:invoke:destructive: %d, want 403", code)
	}
	var still connectorView
	if code := h.do(t, http.MethodGet, "/api/v1/connectors/"+c.ID, nil, &still); code != 200 || still.CatalogHash != "gate-v1" || still.Version != flipped.Version {
		t.Errorf("a refused re-sync wrote something: %d %+v", code, still)
	}

	var applied struct {
		Connector connectorView `json:"connector"`
	}
	if code := resync(h, flipped.Version, &applied); code != 200 || applied.Connector.CatalogHash != plan.BundledHash {
		t.Fatalf("owner's re-sync: %d %+v", code, applied)
	}
	for _, ev := range h.auditEvents(t, context.Background(), f.admin.Org.ID) {
		if ev.Action == "connector.resync" && ev.Outcome == "success" {
			if ev.Meta["declassified"] != true {
				t.Errorf("connector.resync meta = %v; want declassified", ev.Meta)
			}
			return
		}
	}
	t.Error("no successful connector.resync in the audit trail")
}
