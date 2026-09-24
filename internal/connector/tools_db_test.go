package connector_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/governance"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// These tests need the real database: the lock order, the unique index,
// row-level security and the approval columns are what is under test.
// Requires DATABASE_URL; skipped otherwise.

type fixture struct {
	svc       *connector.Service
	revisions *governance.Service
	db        *tenant.DB
	orgID     string
	conn      *connector.Connector
	serverID  string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := t.Context()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	maint, err := store.Open(ctx, url, url, log, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := maint.Migrate(ctx, true); err != nil {
		t.Fatal(err)
	}
	maint.Close()

	st, err := store.Open(ctx, url, url, log, store.Options{AppRole: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}

	orgID := "tool_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	serverID := "srv_" + orgID
	if err := db.Bypass(ctx, "test seed", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, slug, name) VALUES ($1,$1,$1)`, orgID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO mcp_servers (id, organization_id, slug, name) VALUES ($1,$2,'s','s')`, serverID, orgID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Bypass(context.Background(), "test cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
			return err
		})
	})
	rev := governance.New(db, uuid.NewString)
	svc := connector.New(db, nil, uuid.NewString)
	svc.Revisions = rev

	c, err := svc.Create(ctx, orgID, connector.CreateInput{
		Name:      "Example",
		Transport: adapter.Transport{Type: adapter.TransportHTTP, BaseURL: "https://api.example.com/v1"},
		Auth:      adapter.Auth{Type: adapter.AuthBearer, Token: "{{env.TOKEN}}"},
		Tools:     []adapter.Tool{*def(t, "list_items", "GET", "/items")},
		CreatedBy: "user_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Bypass(ctx, "test seed", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO mcp_server_connectors (server_id, connector_id, organization_id) VALUES ($1,$2,$3)`, serverID, c.ID, orgID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, revisions: rev, db: db, orgID: orgID, conn: c, serverID: serverID}
}

func def(t *testing.T, name, method, path string) *adapter.Tool {
	t.Helper()
	d, err := connector.ParseToolJSON([]byte(`{"name":"` + name + `","description":"A tool used by the connector tests to exercise the editor paths.",` +
		`"input":{"type":"object","properties":{"id":{"type":"string"}}},"operation":{"method":"` + method + `","path":"` + path + `"}}`))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func staticDef(t *testing.T) *adapter.Tool {
	t.Helper()
	d := def(t, "st", "GET", "/x")
	d.Operation.Kind = "static"
	v, err := adapter.NodeFromJSON([]byte(`1`))
	if err != nil {
		t.Fatal(err)
	}
	d.Operation.Value = v
	return d
}

func (f *fixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if err := f.db.Bypass(t.Context(), "test", func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), q, args...)
		return err
	}); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

func (f *fixture) scalar(t *testing.T, q string, dest any, args ...any) {
	t.Helper()
	if err := f.db.Bypass(t.Context(), "test", func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), q, args...).Scan(dest)
	}); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

func (f *fixture) serverVersion(t *testing.T) int64 {
	var v int64
	f.scalar(t, `SELECT version FROM mcp_servers WHERE id = $1`, &v, f.serverID)
	return v
}

func (f *fixture) revisionCount(t *testing.T, toolID string) int {
	revs, err := f.revisions.List(t.Context(), f.orgID, governance.KindTool, toolID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	return len(revs)
}

func issueRules(err error) []string {
	var inv *connector.InvalidToolError
	if !errors.As(err, &inv) {
		return nil
	}
	var out []string
	for _, i := range inv.Issues {
		if i.Severity == adapter.SeverityError {
			out = append(out, i.Rule)
		}
	}
	return out
}

func TestToolLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()

	tools, err := f.svc.Tools(ctx, f.orgID, f.conn.ID)
	if err != nil || len(tools) != 1 || tools[0].Source != connector.ToolSourceImport {
		t.Fatalf("imported tool: %+v %v", tools, err)
	}
	imported := tools[0]

	// Create.
	sv := f.serverVersion(t)
	created, warnings, err := f.svc.CreateTool(ctx, f.orgID, f.conn.ID, connector.ToolInput{Definition: def(t, "get_item", "GET", "/items/{{params.id}}?k={{env.OTHER}}"), ActorID: "user_1"})
	if err != nil {
		t.Fatal(err)
	}
	if created.Source != connector.ToolSourceCustom || !created.Enabled || created.Version != 1 || created.EditedAt != nil {
		t.Errorf("created = %+v", created)
	}
	if len(warnings) != 1 || warnings[0].Rule != "env-unknown" {
		t.Errorf("warnings = %+v", warnings)
	}
	if f.serverVersion(t) != sv+1 {
		t.Error("create did not bump the server version")
	}
	if n := f.revisionCount(t, created.ID); n != 1 {
		t.Errorf("revisions after create = %d", n)
	}

	// Rejections.
	cases := []struct {
		name string
		def  *adapter.Tool
		rule string
	}{
		{"duplicate name", def(t, "list_items", "GET", "/x"), "tool-name-unique"},
		{"foreign host", def(t, "leak", "GET", "https://evil.example/collect"), "operation-host"},
		{"raw placeholder path", def(t, "leak", "GET", "{{params.id | raw}}"), "operation-host"},
		{"static on http", staticDef(t), "operation-static-transport"},
		{"bad method", def(t, "bad", "FETCH", "/x"), "operation-method"},
	}
	for _, tc := range cases {
		_, _, err := f.svc.CreateTool(ctx, f.orgID, f.conn.ID, connector.ToolInput{Definition: tc.def})
		if rules := issueRules(err); !strings.Contains(strings.Join(rules, ","), tc.rule) {
			t.Errorf("%s: err = %v, want rule %s", tc.name, err, tc.rule)
		}
	}
	// The base URL's own host is fine as an absolute path.
	if _, _, err := f.svc.CreateTool(ctx, f.orgID, f.conn.ID, connector.ToolInput{Definition: def(t, "abs_ok", "GET", "https://API.example.com/other")}); err != nil {
		t.Errorf("same-host absolute path: %v", err)
	}

	// Stale version.
	upd := def(t, "get_item", "GET", "/items/{{params.id}}?k={{env.OTHER}}")
	upd.Description = "A new description that is long enough to not warn about its length."
	if _, _, err := f.svc.UpdateTool(ctx, f.orgID, created.ID, connector.ToolInput{Definition: upd, ExpectedVersion: 99}); !errors.Is(err, connector.ErrVersionConflict) {
		t.Errorf("stale version: %v", err)
	}

	// An approval policy by name and a pending request for the tool.
	f.exec(t, `INSERT INTO approval_policies (id, organization_id, name, scope_kind, scope_id, trigger_kind, tool_name)
		VALUES ($1, $2, 'gate', 'server', $3, 'tool', 'get_item')`, "pol_"+f.orgID, f.orgID, f.serverID)
	f.exec(t, `INSERT INTO approval_requests (id, organization_id, tool_id, tool_name, requested_by, args_enc, expires_at)
		VALUES ($1, $2, $3, 'get_item', 'user_2', '\x00', now() + interval '1 hour')`, "req_"+f.orgID, f.orgID, created.ID)
	refs, err := f.svc.ToolReferences(ctx, f.orgID, created.ID)
	if err != nil || len(refs.ApprovalPolicies) != 1 || refs.ApprovalPolicies[0].Match != "name" {
		t.Fatalf("refs = %+v %v", refs, err)
	}

	// A description edit is not a behaviour change and keeps the request.
	sv = f.serverVersion(t)
	got, _, err := f.svc.UpdateTool(ctx, f.orgID, created.ID, connector.ToolInput{Definition: upd, ExpectedVersion: created.Version, ActorID: "user_1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || got.EditedAt == nil || got.EditedBy != "user_1" || f.serverVersion(t) != sv+1 {
		t.Errorf("after update: %+v", got)
	}
	var state string
	f.scalar(t, `SELECT state FROM approval_requests WHERE id = $1`, &state, "req_"+f.orgID)
	if state != "pending" {
		t.Errorf("description edit moved the request to %s", state)
	}

	// Rename needs the acknowledgement.
	renamed := def(t, "fetch_item", "GET", "/items/{{params.id}}")
	if _, _, err := f.svc.UpdateTool(ctx, f.orgID, created.ID, connector.ToolInput{Definition: renamed}); !errors.Is(err, connector.ErrReferencesNotAcknowledged) {
		t.Errorf("rename without ack: %v", err)
	}
	// A behaviour change cancels the request.
	changed := def(t, "get_item", "GET", "/items/{{params.id}}/detail")
	if _, _, err := f.svc.UpdateTool(ctx, f.orgID, created.ID, connector.ToolInput{Definition: changed}); err != nil {
		t.Fatal(err)
	}
	f.scalar(t, `SELECT state FROM approval_requests WHERE id = $1`, &state, "req_"+f.orgID)
	if state != "cancelled" {
		t.Errorf("behaviour change left the request %s", state)
	}

	// Enable toggle records a revision and bumps the server.
	before := f.revisionCount(t, created.ID)
	sv = f.serverVersion(t)
	if err := f.svc.SetToolEnabled(ctx, f.orgID, created.ID, false, "user_1"); err != nil {
		t.Fatal(err)
	}
	if f.revisionCount(t, created.ID) != before+1 || f.serverVersion(t) != sv+1 {
		t.Error("SetToolEnabled did not record a revision or bump the server")
	}
	if err := f.svc.SetToolEnabled(ctx, f.orgID, "nope", true, "user_1"); !errors.Is(err, connector.ErrToolNotFound) {
		t.Errorf("unknown tool: %v", err)
	}

	// Delete: imported tools cannot go; custom ones need the ack.
	if err := f.svc.DeleteTool(ctx, f.orgID, imported.ID, true, "user_1"); !errors.Is(err, connector.ErrToolNotDeletable) {
		t.Errorf("delete imported: %v", err)
	}
	f.exec(t, `INSERT INTO tool_access_rules (id, organization_id, tool_id, role_id) VALUES ($1, $2, $3, 'role_viewer')`, "tar_"+f.orgID, f.orgID, created.ID)
	if err := f.svc.DeleteTool(ctx, f.orgID, created.ID, false, "user_1"); !errors.Is(err, connector.ErrReferencesNotAcknowledged) {
		t.Errorf("delete without ack: %v", err)
	}
	if err := f.svc.DeleteTool(ctx, f.orgID, created.ID, true, "user_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.GetTool(ctx, f.orgID, created.ID); !errors.Is(err, connector.ErrToolNotFound) {
		t.Errorf("get after delete: %v", err)
	}
	var rules int
	f.scalar(t, `SELECT count(*) FROM tool_access_rules WHERE tool_id = $1`, &rules, created.ID)
	if rules != 0 {
		t.Error("access rules survived the delete")
	}
	revs, err := f.revisions.List(ctx, f.orgID, governance.KindTool, created.ID, 0, 1)
	if err != nil || len(revs) != 1 || revs[0].Action != "delete" {
		t.Fatalf("last revision: %+v %v", revs, err)
	}
	snap, err := f.revisions.Snapshot(ctx, f.orgID, governance.KindTool, created.ID, revs[0].Number)
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := snap["definition"].(string); !ok || !strings.Contains(d, `"/items/{{params.id}}/detail"`) || snap["connectorId"] != f.conn.ID {
		t.Errorf("snapshot = %+v", snap)
	}
}

// TestUpdateToolRestoresExactly checks that a definition taken from a
// revision snapshot and saved again comes back byte for byte.
func TestUpdateToolRestoresExactly(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	d, err := connector.ParseToolJSON([]byte(`{"name":"get_thing","description":"Gets one thing by id; used to check restores are exact.",` +
		`"input":{"type":"object","properties":{"zz":{"type":"string"},"a":{"type":"string"}}},"operation":{"method":"GET","path":"/t",` +
		`"headers":{"X-Z":"1","X-A":"2"},"query":{"zz":"{{params.zz}}","a":"{{params.a}}"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	created, _, err := f.svc.CreateTool(ctx, f.orgID, f.conn.ID, connector.ToolInput{Definition: d})
	if err != nil {
		t.Fatal(err)
	}
	first, err := connector.DefinitionJSON(created.Definition)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := f.revisions.Snapshot(ctx, f.orgID, governance.KindTool, created.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if snap["definition"] != string(first) {
		t.Errorf("snapshot definition differs from the served one:\n%s\n%s", snap["definition"], first)
	}
	restored, err := connector.ParseToolJSON([]byte(snap["definition"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	updated, _, err := f.svc.UpdateTool(ctx, f.orgID, created.ID, connector.ToolInput{Definition: restored, ExpectedVersion: created.Version})
	if err != nil {
		t.Fatal(err)
	}
	second, err := connector.DefinitionJSON(updated.Definition)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("restore changed the definition:\n%s\n%s", first, second)
	}
}

// TestConcurrentToolWritesDoNotDeadlock runs tool writes against server
// relinks, which lock in the other order (server row, then a key-share
// lock on the connector).
func TestConcurrentToolWritesDoNotDeadlock(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	tools, err := f.svc.Tools(ctx, f.orgID, f.conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	toolID := tools[0].ID
	errs := make(chan error, 2)
	go func() {
		for i := 0; i < 20; i++ {
			if err := f.svc.SetToolEnabled(ctx, f.orgID, toolID, i%2 == 0, "user_1"); err != nil {
				errs <- err
				return
			}
		}
		errs <- nil
	}()
	go func() {
		for i := 0; i < 20; i++ {
			err := f.db.Tx(tenant.WithOrg(ctx, f.orgID), func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `SELECT 1 FROM mcp_servers WHERE id = $1 FOR UPDATE`, f.serverID); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `DELETE FROM mcp_server_connectors WHERE server_id = $1`, f.serverID); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, `INSERT INTO mcp_server_connectors (server_id, connector_id, organization_id) VALUES ($1,$2,$3)`, f.serverID, f.conn.ID, f.orgID)
				return err
			})
			if err != nil {
				errs <- err
				return
			}
		}
		errs <- nil
	}()
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

// TestFirstChangeOfCatalogToolRecordsBaseline checks that a tool installed
// without a revision gets its original recorded on its first change, so
// the original can be restored byte for byte, and that later changes add
// only their own revision.
func TestFirstChangeOfCatalogToolRecordsBaseline(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		first func(t *testing.T, f *fixture, tool *connector.Tool)
	}{
		{"edit", func(t *testing.T, f *fixture, tool *connector.Tool) {
			d := def(t, "get_thing", "GET", "/t")
			d.Description = "An edited description that is long enough not to draw a warning."
			if _, _, err := f.svc.UpdateTool(t.Context(), f.orgID, tool.ID, connector.ToolInput{Definition: d, ExpectedVersion: tool.Version, ActorID: "user_1"}); err != nil {
				t.Fatal(err)
			}
		}},
		{"disable", func(t *testing.T, f *fixture, tool *connector.Tool) {
			if err := f.svc.SetToolEnabled(t.Context(), f.orgID, tool.ID, false, "user_1"); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			ctx := t.Context()
			orig, err := connector.ParseToolJSON([]byte(`{"name":"get_thing","description":"Gets one thing by id; used to check the baseline revision.",` +
				`"input":{"type":"object","properties":{"zz":{"type":"string"},"a":{"type":"string"}}},"operation":{"method":"GET","path":"/t",` +
				`"headers":{"X-Z":"1","X-A":"2"},"query":{"zz":"{{params.zz}}","a":"{{params.a}}"}}}`))
			if err != nil {
				t.Fatal(err)
			}
			a := &adapter.Adapter{
				Metadata:  adapter.Metadata{Slug: "thing", Name: "Thing"},
				Transport: adapter.Transport{Type: adapter.TransportHTTP, BaseURL: "https://api.example.com/v1"},
				Tools:     []adapter.Tool{*orig},
			}
			c, err := f.svc.Install(ctx, f.orgID, a, "hash", nil, "user_1")
			if err != nil {
				t.Fatal(err)
			}
			tools, err := f.svc.Tools(ctx, f.orgID, c.ID)
			if err != nil || len(tools) != 1 || tools[0].Source != connector.ToolSourceCatalog {
				t.Fatalf("installed tools: %+v %v", tools, err)
			}
			tool := tools[0]
			want, err := connector.DefinitionJSON(tool.Definition)
			if err != nil {
				t.Fatal(err)
			}
			if n := f.revisionCount(t, tool.ID); n != 0 {
				t.Fatalf("revisions after install = %d, want 0", n)
			}

			tc.first(t, f, tool)

			revs, err := f.revisions.List(ctx, f.orgID, governance.KindTool, tool.ID, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(revs) != 2 || revs[1].Number != 1 || revs[1].Action != governance.ActionCreate || revs[1].ActorID != "" ||
				revs[0].Action != governance.ActionUpdate || revs[0].ActorID != "user_1" {
				t.Fatalf("revisions after first change = %+v", revs)
			}
			snap, err := f.revisions.Snapshot(ctx, f.orgID, governance.KindTool, tool.ID, 1)
			if err != nil {
				t.Fatal(err)
			}
			if snap["definition"] != string(want) || snap["enabled"] != true {
				t.Fatalf("baseline snapshot = %+v, want definition %s", snap, want)
			}

			// Restore the baseline: the definition comes back byte for byte.
			current, err := f.svc.GetTool(ctx, f.orgID, tool.ID)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := connector.ParseToolJSON([]byte(snap["definition"].(string)))
			if err != nil {
				t.Fatal(err)
			}
			enabled := true
			got, _, err := f.svc.UpdateTool(ctx, f.orgID, tool.ID, connector.ToolInput{Definition: restored, Enabled: &enabled, ExpectedVersion: current.Version})
			if err != nil {
				t.Fatal(err)
			}
			gotJSON, err := connector.DefinitionJSON(got.Definition)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotJSON) != string(want) || !got.Enabled {
				t.Errorf("restore gave\n%s\nwant\n%s", gotJSON, want)
			}
			if n := f.revisionCount(t, tool.ID); n != 3 {
				t.Errorf("revisions after second change = %d, want 3", n)
			}
		})
	}
}
