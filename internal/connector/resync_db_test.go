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

// bundledAs serves a as the bundled adapter with content hash hash, which
// earlier catalogs had as previous.
func bundledAs(a *adapter.Adapter, hash string, previous ...string) connector.BundledFunc {
	return func(slug string) (*adapter.Adapter, adapter.IndexEntry, error) {
		if slug != a.Metadata.Slug {
			return nil, adapter.IndexEntry{}, fmt.Errorf("no adapter %s: %w", slug, fs.ErrNotExist)
		}
		return a, adapter.IndexEntry{Slug: slug, ContentHash: hash, PreviousHashes: previous}, nil
	}
}

func described(t *testing.T, name, method, path, description string) *adapter.Tool {
	t.Helper()
	d := def(t, name, method, path)
	d.Description = description
	return d
}

// resyncV1 and resyncV2 are two versions of one adapter: v2 rewrites
// "change", drops "drop", adds "added", has new text for "hand_edited",
// and new instructions.
func resyncV1(t *testing.T) *adapter.Adapter {
	return resyncAdapter(t, "Version one.",
		def(t, "keep", "GET", "/keep"),
		def(t, "change", "GET", "/change"),
		def(t, "drop", "GET", "/drop"),
		def(t, "hand_edited", "GET", "/edited"),
	)
}

func resyncV2(t *testing.T) *adapter.Adapter {
	return resyncAdapter(t, "Version two.",
		def(t, "keep", "GET", "/keep"),
		def(t, "change", "POST", "/change"),
		described(t, "hand_edited", "GET", "/edited", "The catalog's newer description of this tool, long enough to pass."),
		def(t, "added", "GET", "/added"),
	)
}

func (f *fixture) toolsByName(t *testing.T, connectorID string) map[string]*connector.Tool {
	t.Helper()
	tools, err := f.svc.Tools(t.Context(), f.orgID, connectorID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*connector.Tool{}
	for _, tl := range tools {
		out[tl.Name] = tl
	}
	return out
}

// TestApplyResync installs version 1 of an adapter, changes it by hand the
// ways a person can, and re-syncs it to version 2.
func TestApplyResync(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := t.Context()

	c, err := f.svc.Install(ctx, f.orgID, resyncV1(t), "hash-v1", nil, "user_1")
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO mcp_server_connectors (server_id, connector_id, organization_id) VALUES ($1,$2,$3)`, f.serverID, c.ID, f.orgID)
	installed := f.toolsByName(t, c.ID)

	// A person edits one catalog tool, adds a custom one, and points the
	// connector at their own host.
	edited := described(t, "hand_edited", "GET", "/edited", "Someone's own description of this tool, long enough to pass.")
	if _, _, err := f.svc.UpdateTool(ctx, f.orgID, installed["hand_edited"].ID, connector.ToolInput{
		Definition: edited, ExpectedVersion: installed["hand_edited"].Version, ActorID: "user_1"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.CreateTool(ctx, f.orgID, c.ID, connector.ToolInput{Definition: def(t, "mine", "GET", "/mine"), ActorID: "user_1"}); err != nil {
		t.Fatal(err)
	}
	own := adapter.Transport{Type: adapter.TransportHTTP, BaseURL: "https://proxy.internal.example/thing"}
	if _, err := f.svc.Update(ctx, f.orgID, c.ID, connector.UpdateInput{Transport: &own, ActorID: "user_1"}); err != nil {
		t.Fatal(err)
	}
	// An older replica labelled one catalog tool an import.
	f.exec(t, `UPDATE tools SET source = 'import' WHERE id = $1`, installed["keep"].ID)
	// Requests waiting on the tools whose behaviour changes or which go.
	for _, name := range []string{"change", "drop"} {
		f.exec(t, `INSERT INTO approval_requests (id, organization_id, tool_id, tool_name, requested_by, args_enc, expires_at)
			VALUES ($1, $2, $3, $4, 'user_2', '\x00', now() + interval '1 hour')`, "req_"+name+"_"+f.orgID, f.orgID, installed[name].ID, name)
	}

	bundled := bundledAs(resyncV2(t), "hash-v2", "hash-v1")
	p, err := f.svc.PlanResync(ctx, f.orgID, c.ID, bundled)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Outdated() || len(p.Add) != 1 || len(p.Update) != 1 || len(p.Remove) != 1 || len(p.Skipped) != 1 ||
		p.Skipped[0].Name != "hand_edited" || len(p.Fields) != 1 || len(p.NotApplied) != 1 || p.NotApplied[0].Field != "transport" ||
		len(p.Relabel) != 1 || p.Relabel[0].Name != "keep" {
		t.Fatalf("plan = add %+v update %+v remove %+v skipped %+v fields %+v not applied %+v relabel %+v",
			p.Add, p.Update, p.Remove, p.Skipped, p.Fields, p.NotApplied, p.Relabel)
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
	if after.Transport.BaseURL != own.BaseURL {
		t.Errorf("transport after = %+v; re-sync must leave the operator's host alone", after.Transport)
	}
	if v := f.serverVersion(t); v != serverBefore+1 {
		t.Errorf("server version = %d, want %d: cached tool lists would not rebuild", v, serverBefore+1)
	}

	tools := f.toolsByName(t, c.ID)
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
	if tl := tools["keep"]; tl == nil || tl.Version != installed["keep"].Version || tl.Source != connector.ToolSourceCatalog {
		t.Errorf("the unchanged tool = %+v; want it relabelled and not rewritten", tl)
	}

	for _, name := range []string{"change", "drop"} {
		var state string
		f.scalar(t, `SELECT state FROM approval_requests WHERE id = $1`, &state, "req_"+name+"_"+f.orgID)
		if state != "cancelled" {
			t.Errorf("approval request on %s is %s, want cancelled", name, state)
		}
	}

	// A revision of the connector (create, the transport edit, re-sync),
	// and of each tool touched: the change and the removal have a
	// baseline under them, the addition does not.
	revs, err := f.revisions.List(ctx, f.orgID, governance.KindConnector, c.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 3 || revs[0].Action != governance.ActionUpdate || revs[0].ActorID != "user_1" {
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

	// Now up to date: the plan is empty but still reports the skipped tool
	// and the transport, and applying again changes nothing.
	p, err = f.svc.PlanResync(ctx, f.orgID, c.ID, bundled)
	if err != nil {
		t.Fatal(err)
	}
	if p.Outdated() || !p.Empty() || len(p.Skipped) != 1 || len(p.NotApplied) != 1 {
		t.Errorf("plan after apply: outdated %v empty %v skipped %+v not applied %+v", p.Outdated(), p.Empty(), p.Skipped, p.NotApplied)
	}
	if _, err := f.svc.ApplyResync(ctx, f.orgID, c.ID, bundled, connector.ResyncInput{
		CatalogHash: "hash-v2", ExpectedVersion: after.Version, ActorID: "user_1"}); err != nil {
		t.Fatal(err)
	}
	if again, err := f.svc.Get(ctx, f.orgID, c.ID); err != nil || again.Version != after.Version {
		t.Errorf("a second apply moved the version to %d (%v)", again.Version, err)
	}
}

// TestResyncOnlyMovesForward: a connector whose hash this binary does not
// know may come from a newer catalog, as during a rolling upgrade or after
// a rollback. It is neither outdated nor re-syncable.
func TestResyncOnlyMovesForward(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := t.Context()
	c, err := f.svc.Install(ctx, f.orgID, resyncV2(t), "hash-v3", nil, "user_1")
	if err != nil {
		t.Fatal(err)
	}
	older := bundledAs(resyncV1(t), "hash-v2", "hash-v1")
	if _, err := f.svc.PlanResync(ctx, f.orgID, c.ID, older); !errors.Is(err, connector.ErrCatalogNotBehind) {
		t.Errorf("plan from an older binary: err = %v, want ErrCatalogNotBehind", err)
	}
	if _, err := f.svc.ApplyResync(ctx, f.orgID, c.ID, older, connector.ResyncInput{
		CatalogHash: "hash-v2", ExpectedVersion: c.Version, ActorID: "user_1"}); !errors.Is(err, connector.ErrCatalogNotBehind) {
		t.Errorf("apply from an older binary: err = %v, want ErrCatalogNotBehind", err)
	}
	after, err := f.svc.Get(ctx, f.orgID, c.ID)
	if err != nil || after.CatalogHash != "hash-v3" || after.Version != c.Version || after.Instructions != "Version two." {
		t.Errorf("connector after a refused downgrade = %+v (%v)", after, err)
	}
}

// TestApplyResyncAuthorizesThePlanItApplies: the permission check runs on
// the plan rebuilt under the connector's lock. Here the connector's
// read-only flag changes before the apply, as a concurrent edit would; the
// check sees the connector as it is when written, and refusing rolls the
// whole re-sync back.
func TestApplyResyncAuthorizesThePlanItApplies(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := t.Context()
	c, err := f.svc.Install(ctx, f.orgID, resyncV1(t), "hash-v1", nil, "user_1")
	if err != nil {
		t.Fatal(err)
	}
	if !c.ReadOnly {
		t.Fatal("a catalog install starts read-only")
	}
	bundled := bundledAs(resyncV2(t), "hash-v2", "hash-v1")

	writable := false
	flipped, err := f.svc.Update(ctx, f.orgID, c.ID, connector.UpdateInput{ReadOnly: &writable, ActorID: "user_2"})
	if err != nil {
		t.Fatal(err)
	}
	var seen *connector.ResyncPlan
	refusal := errors.New("refused")
	_, err = f.svc.ApplyResync(ctx, f.orgID, c.ID, bundled, connector.ResyncInput{
		CatalogHash: "hash-v2", ExpectedVersion: flipped.Version, ActorID: "user_1",
		Authorize: func(p *connector.ResyncPlan) error { seen = p; return refusal },
	})
	if !errors.Is(err, refusal) {
		t.Fatalf("err = %v, want the refusal", err)
	}
	if seen == nil || seen.Connector.ReadOnly || seen.Connector.Version != flipped.Version {
		t.Errorf("authorised plan = %+v; want the connector as written (writable, version %d)", seen, flipped.Version)
	}
	after, err := f.svc.Get(ctx, f.orgID, c.ID)
	if err != nil || after.CatalogHash != "hash-v1" || after.Version != flipped.Version || after.Instructions != "Version one." {
		t.Errorf("a refused re-sync wrote something: %+v (%v)", after, err)
	}
	if _, ok := f.toolsByName(t, c.ID)["drop"]; !ok {
		t.Error("a refused re-sync removed a tool")
	}

	// The version the caller reviewed must be the one under the lock; the
	// check is not even asked otherwise.
	seen = nil
	if _, err := f.svc.ApplyResync(ctx, f.orgID, c.ID, bundled, connector.ResyncInput{
		CatalogHash: "hash-v2", ExpectedVersion: c.Version, ActorID: "user_1",
		Authorize: func(p *connector.ResyncPlan) error { seen = p; return nil },
	}); !errors.Is(err, connector.ErrResyncStale) || seen != nil {
		t.Errorf("apply against the version before the edit: err = %v, authorised %v; want ErrResyncStale unasked", err, seen != nil)
	}
}

// TestResyncIsolatesTenants: another organisation cannot plan or apply a
// re-sync of this one's connector, and this one's re-sync leaves the other
// organisation's rows alone, although both installed the same adapter.
func TestResyncIsolatesTenants(t *testing.T) {
	t.Parallel()
	a, b := newFixture(t), newFixture(t)
	ctx := t.Context()
	bundled := bundledAs(resyncV2(t), "hash-v2", "hash-v1")

	ca, _ := installWithRefs(t, a)
	cb, toolsB := installWithRefs(t, b)
	serverB := b.serverVersion(t)

	// B asks for A's connector by id and finds nothing.
	if _, err := b.svc.PlanResync(ctx, b.orgID, ca.ID, bundled); !errors.Is(err, connector.ErrNotFound) {
		t.Errorf("B plans A's connector: err = %v, want ErrNotFound", err)
	}
	if _, err := b.svc.ApplyResync(ctx, b.orgID, ca.ID, bundled, connector.ResyncInput{
		CatalogHash: "hash-v2", ExpectedVersion: ca.Version, ActorID: "user_b"}); !errors.Is(err, connector.ErrNotFound) {
		t.Errorf("B applies A's connector: err = %v, want ErrNotFound", err)
	}
	if got, err := a.svc.Get(ctx, a.orgID, ca.ID); err != nil || got.CatalogHash != "hash-v1" || got.Version != ca.Version {
		t.Errorf("A's connector after B's attempts = %+v (%v)", got, err)
	}

	// A re-syncs; B's rows of the same shape stay as they were.
	if _, err := a.svc.ApplyResync(ctx, a.orgID, ca.ID, bundled, connector.ResyncInput{
		CatalogHash: "hash-v2", ExpectedVersion: ca.Version, ActorID: "user_a"}); err != nil {
		t.Fatal(err)
	}
	if got, err := b.svc.Get(ctx, b.orgID, cb.ID); err != nil || got.CatalogHash != "hash-v1" || got.Version != cb.Version {
		t.Errorf("B's connector after A's re-sync = %+v (%v)", got, err)
	}
	after := b.toolsByName(t, cb.ID)
	for name, tl := range toolsB {
		if got := after[name]; got == nil || got.Version != tl.Version {
			t.Errorf("B's tool %s after A's re-sync = %+v", name, got)
		}
	}
	var rules int
	b.scalar(t, `SELECT count(*) FROM tool_access_rules WHERE organization_id = $1`, &rules, b.orgID)
	if rules != 1 {
		t.Errorf("B has %d access rules after A's re-sync, want 1", rules)
	}
	var pending int
	b.scalar(t, `SELECT count(*) FROM approval_requests WHERE organization_id = $1 AND state = 'pending'`, &pending, b.orgID)
	if pending != 2 {
		t.Errorf("B has %d pending approval requests after A's re-sync, want 2", pending)
	}
	if v := b.serverVersion(t); v != serverB {
		t.Errorf("B's server version moved from %d to %d", serverB, v)
	}
	var rulesA int
	a.scalar(t, `SELECT count(*) FROM tool_access_rules WHERE organization_id = $1`, &rulesA, a.orgID)
	if rulesA != 0 {
		t.Errorf("A still has %d access rules on its removed tool", rulesA)
	}
}

// installWithRefs installs version 1 on f's server, with pending approval
// requests on "change" and "drop" and a deny rule on "drop": the rows a
// re-sync cancels and deletes.
func installWithRefs(t *testing.T, f *fixture) (*connector.Connector, map[string]*connector.Tool) {
	t.Helper()
	c, err := f.svc.Install(t.Context(), f.orgID, resyncV1(t), "hash-v1", nil, "user_1")
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO mcp_server_connectors (server_id, connector_id, organization_id) VALUES ($1,$2,$3)`, f.serverID, c.ID, f.orgID)
	tools := f.toolsByName(t, c.ID)
	for _, name := range []string{"change", "drop"} {
		f.exec(t, `INSERT INTO approval_requests (id, organization_id, tool_id, tool_name, requested_by, args_enc, expires_at)
			VALUES ($1, $2, $3, $4, 'user_2', '\x00', now() + interval '1 hour')`, "req_"+name+"_"+f.orgID, f.orgID, tools[name].ID, name)
	}
	f.exec(t, `INSERT INTO tool_access_rules (id, organization_id, tool_id, role_id, effect) VALUES ($1, $2, $3, 'role_editor', 'deny')`,
		"rule_"+f.orgID, f.orgID, tools["drop"].ID)
	return c, tools
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
