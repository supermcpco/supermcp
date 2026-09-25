package e2e

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
)

type resyncPlan struct {
	BundledHash string `json:"bundledHash"`
	Outdated    bool   `json:"outdated"`
	Version     int64  `json:"version"`
	Update      []struct {
		Name    string   `json:"name"`
		Changed []string `json:"changed"`
	} `json:"update"`
	Add    []struct{ Name string } `json:"add"`
	Remove []struct{ Name string } `json:"remove"`
}

type connectorView struct {
	ID              string `json:"id"`
	CatalogOutdated bool   `json:"catalogOutdated"`
	Version         int64  `json:"version"`
}

// TestCatalogResync installs a catalog adapter, makes the installed copy
// look like an older version of it, and re-syncs it through the API.
func TestCatalogResync(t *testing.T) {
	f := newToolFixture(t)
	h := f.h
	const tool = "bundesbank_get_exchange_rates"

	var installed connectorView
	if code := h.do(t, http.MethodPost, "/api/v1/connectors/install", map[string]any{"slug": "bundesbank"}, &installed); code != 200 {
		t.Fatalf("install: %d", code)
	}
	// An older binary installed it: its hash and one tool's text differ
	// from what this one carries. Only an upgrade produces that state.
	ctx := context.Background()
	if err := h.db.Bypass(ctx, "e2e resync", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE connectors SET catalog_hash = 'older' WHERE id = $1`, installed.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE tools SET definition = jsonb_set(definition, '{description}', '"The older description."')
			WHERE connector_id = $1 AND name = $2`, installed.ID, tool); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO mcp_server_connectors (server_id, connector_id, organization_id) VALUES ($1, $2, $3)`,
			f.srv.ID, installed.ID, f.admin.Org.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if served := f.mcpTools(t)[tool]; served == nil || served.Description != "The older description." {
		t.Fatalf("served before the re-sync: %+v", served)
	}

	var list []connectorView
	if code := h.do(t, http.MethodGet, "/api/v1/connectors", nil, &list); code != 200 {
		t.Fatalf("list: %d", code)
	}
	outdated := map[string]bool{}
	for _, c := range list {
		outdated[c.ID] = c.CatalogOutdated
	}
	if !outdated[installed.ID] || outdated[f.conn.ID] {
		t.Fatalf("catalogOutdated = %v; want only %s", outdated, installed.ID)
	}

	var plan resyncPlan
	if code := h.do(t, http.MethodGet, "/api/v1/connectors/"+installed.ID+"/resync", nil, &plan); code != 200 {
		t.Fatalf("preview: %d", code)
	}
	if !plan.Outdated || len(plan.Add) != 0 || len(plan.Remove) != 0 || len(plan.Update) != 1 ||
		plan.Update[0].Name != tool || !slices.Equal(plan.Update[0].Changed, []string{"description"}) {
		t.Fatalf("preview = %+v", plan)
	}
	var e apiError
	if code := h.do(t, http.MethodGet, "/api/v1/connectors/"+f.conn.ID+"/resync", nil, &e); code != http.StatusConflict {
		t.Errorf("preview of an imported connector: %d %s, want 409", code, e.Detail)
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
	if applied.Connector.CatalogOutdated || applied.Connector.Version != plan.Version+1 || len(applied.Applied.Update) != 1 {
		t.Errorf("apply = %+v", applied)
	}
	if served := f.mcpTools(t)[tool]; served == nil || served.Description == "The older description." {
		t.Errorf("MCP clients are still served the old tool: %+v", served)
	}

	events := h.auditEvents(t, ctx, f.admin.Org.ID)
	if !slices.Contains(actions(events), "connector.resync") {
		t.Errorf("no connector.resync in the audit trail: %v", actions(events))
	}
}
