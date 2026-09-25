package connector_test

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/governance"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// resyncAdapter builds a version of the "thing" adapter.
func resyncAdapter(t *testing.T, instructions string, tools ...*adapter.Tool) *adapter.Adapter {
	t.Helper()
	a := &adapter.Adapter{
		Metadata:     adapter.Metadata{Slug: "thing", Name: "Thing"},
		Instructions: instructions,
		Transport:    adapter.Transport{Type: adapter.TransportHTTP, BaseURL: "https://api.example.com/v1"},
	}
	for _, d := range tools {
		a.Tools = append(a.Tools, *d)
	}
	return a
}

func bundledAs(a *adapter.Adapter, hash string) connector.BundledFunc {
	return func(slug string) (*adapter.Adapter, string, error) {
		if slug != a.Metadata.Slug {
			return nil, "", fmt.Errorf("no adapter %s: %w", slug, fs.ErrNotExist)
		}
		return a, hash, nil
	}
}

func described(t *testing.T, name, method, path, description string) *adapter.Tool {
	t.Helper()
	d := def(t, name, method, path)
	d.Description = description
	return d
}

// TestApplyResync installs version 1 of an adapter, changes it by hand the
// ways a person can, and re-syncs it to version 2.
func TestApplyResync(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := t.Context()

	v1 := resyncAdapter(t, "Version one.",
		def(t, "keep", "GET", "/keep"),
		def(t, "change", "GET", "/change"),
		def(t, "drop", "GET", "/drop"),
		def(t, "hand_edited", "GET", "/edited"),
	)
	c, err := f.svc.Install(ctx, f.orgID, v1, "hash-v1", nil, "user_1")
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO mcp_server_connectors (server_id, connector_id, organization_id) VALUES ($1,$2,$3)`, f.serverID, c.ID, f.orgID)
	byName := func() map[string]*connector.Tool {
		tools, err := f.svc.Tools(ctx, f.orgID, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]*connector.Tool{}
		for _, tl := range tools {
			out[tl.Name] = tl
		}
		return out
	}
	installed := byName()

	// A person edits one catalog tool and adds a custom one.
	edited := described(t, "hand_edited", "GET", "/edited", "Someone's own description of this tool, long enough to pass.")
	if _, _, err := f.svc.UpdateTool(ctx, f.orgID, installed["hand_edited"].ID, connector.ToolInput{
		Definition: edited, ExpectedVersion: installed["hand_edited"].Version, ActorID: "user_1"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.CreateTool(ctx, f.orgID, c.ID, connector.ToolInput{Definition: def(t, "mine", "GET", "/mine"), ActorID: "user_1"}); err != nil {
		t.Fatal(err)
	}
	// Requests waiting on the tools whose behaviour changes or which go.
	for _, name := range []string{"change", "drop"} {
		f.exec(t, `INSERT INTO approval_requests (id, organization_id, tool_id, tool_name, requested_by, args_enc, expires_at)
			VALUES ($1, $2, $3, $4, 'user_2', '\x00', now() + interval '1 hour')`, "req_"+name+"_"+f.orgID, f.orgID, installed[name].ID, name)
	}

	v2 := resyncAdapter(t, "Version two.",
		def(t, "keep", "GET", "/keep"),
		def(t, "change", "POST", "/change"),
		described(t, "hand_edited", "GET", "/edited", "The catalog's newer description of this tool, long enough to pass."),
		def(t, "added", "GET", "/added"),
	)
	bundled := bundledAs(v2, "hash-v2")

	p, err := f.svc.PlanResync(ctx, f.orgID, c.ID, bundled)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Outdated() || len(p.Add) != 1 || len(p.Update) != 1 || len(p.Remove) != 1 || len(p.Skipped) != 1 ||
		p.Skipped[0].Name != "hand_edited" || len(p.Fields) != 1 {
		t.Fatalf("plan = add %+v update %+v remove %+v skipped %+v fields %+v", p.Add, p.Update, p.Remove, p.Skipped, p.Fields)
	}

	before, err := f.svc.Get(ctx, f.orgID, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	serverBefore := f.serverVersion(t)

	// A stale review is refused and changes nothing.
	for _, in := range []connector.ResyncInput{
		{CatalogHash: "hash-v2", ExpectedVersion: before.Version - 1, ActorID: "user_1"},
		{CatalogHash: "hash-other", ExpectedVersion: before.Version, ActorID: "user_1"},
	} {
		if _, err := f.svc.ApplyResync(ctx, f.orgID, c.ID, bundled, in); !errors.Is(err, connector.ErrResyncStale) {
			t.Fatalf("apply %+v: err = %v, want ErrResyncStale", in, err)
		}
	}

	if _, err := f.svc.ApplyResync(ctx, f.orgID, c.ID, bundled, connector.ResyncInput{
		CatalogHash: "hash-v2", ExpectedVersion: before.Version, ActorID: "user_1"}); err != nil {
		t.Fatal(err)
	}

	after, err := f.svc.Get(ctx, f.orgID, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.CatalogHash != "hash-v2" || after.Version != before.Version+1 || after.Instructions != "Version two." {
		t.Errorf("connector after = hash %s version %d instructions %q; want hash-v2, %d, Version two.",
			after.CatalogHash, after.Version, after.Instructions, before.Version+1)
	}
	if v := f.serverVersion(t); v != serverBefore+1 {
		t.Errorf("server version = %d, want %d: cached tool lists would not rebuild", v, serverBefore+1)
	}

	tools := byName()
	if _, ok := tools["drop"]; ok {
		t.Error("the tool dropped from the adapter is still there")
	}
	if tl := tools["added"]; tl == nil || tl.Source != connector.ToolSourceCatalog || !tl.Enabled {
		t.Errorf("added tool = %+v", tl)
	}
	if tl := tools["change"]; tl == nil || tl.Definition.Operation.Method != "POST" || tl.Version != installed["change"].Version+1 || tl.EditedAt != nil {
		t.Errorf("changed tool = %+v", tl)
	}
	if tl := tools["hand_edited"]; tl == nil || tl.Definition.Description != edited.Description {
		t.Errorf("the hand-edited tool was overwritten: %+v", tl)
	}
	if tl := tools["mine"]; tl == nil || tl.Source != connector.ToolSourceCustom {
		t.Errorf("the custom tool = %+v", tl)
	}
	if tl := tools["keep"]; tl == nil || tl.Version != installed["keep"].Version {
		t.Errorf("the unchanged tool was rewritten: %+v", tl)
	}

	for _, name := range []string{"change", "drop"} {
		var state string
		f.scalar(t, `SELECT state FROM approval_requests WHERE id = $1`, &state, "req_"+name+"_"+f.orgID)
		if state != "cancelled" {
			t.Errorf("approval request on %s is %s, want cancelled", name, state)
		}
	}

	// A revision of the connector, and of each tool touched: the change
	// and the removal have a baseline under them, the addition does not.
	revs, err := f.revisions.List(ctx, f.orgID, governance.KindConnector, c.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 2 || revs[0].Action != governance.ActionUpdate || revs[0].ActorID != "user_1" {
		t.Errorf("connector revisions = %+v", revs)
	}
	for name, want := range map[string]int{"change": 2, "drop": 2} {
		if n := f.revisionCount(t, installed[name].ID); n != want {
			t.Errorf("%s: %d revisions, want %d", name, n, want)
		}
	}
	if n := f.revisionCount(t, tools["added"].ID); n != 1 {
		t.Errorf("added: %d revisions, want 1", n)
	}

	// Now up to date: the plan is empty but still reports the skipped
	// tool, and applying again changes nothing.
	p, err = f.svc.PlanResync(ctx, f.orgID, c.ID, bundled)
	if err != nil {
		t.Fatal(err)
	}
	if p.Outdated() || !p.Empty() || len(p.Skipped) != 1 {
		t.Errorf("plan after apply: outdated %v empty %v skipped %+v", p.Outdated(), p.Empty(), p.Skipped)
	}
	if _, err := f.svc.ApplyResync(ctx, f.orgID, c.ID, bundled, connector.ResyncInput{
		CatalogHash: "hash-v2", ExpectedVersion: after.Version, ActorID: "user_1"}); err != nil {
		t.Fatal(err)
	}
	if again, err := f.svc.Get(ctx, f.orgID, c.ID); err != nil || again.Version != after.Version {
		t.Errorf("a second apply moved the version to %d (%v)", again.Version, err)
	}
}

func TestResyncRefusesWhatItCannotCompare(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := t.Context()
	bundled := bundledAs(resyncAdapter(t, ""), "h")

	// The fixture's connector is hand-made.
	if _, err := f.svc.PlanResync(ctx, f.orgID, f.conn.ID, bundled); !errors.Is(err, connector.ErrNotFromCatalog) {
		t.Errorf("hand-made connector: err = %v, want ErrNotFromCatalog", err)
	}
	other := resyncAdapter(t, "")
	other.Metadata.Slug = "retired"
	c, err := f.svc.Install(ctx, f.orgID, other, "h", nil, "user_1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.PlanResync(ctx, f.orgID, c.ID, bundled); !errors.Is(err, connector.ErrNotInCatalog) {
		t.Errorf("adapter gone from the catalog: err = %v, want ErrNotInCatalog", err)
	}
	if _, err := f.svc.PlanResync(ctx, f.orgID, "con_missing", bundled); !errors.Is(err, connector.ErrNotFound) {
		t.Errorf("unknown connector: err = %v, want ErrNotFound", err)
	}
}
