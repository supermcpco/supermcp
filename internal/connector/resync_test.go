package connector

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/supermcpco/supermcp/internal/catalog"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// storedLike returns a definition the way it comes back from the tools
// table: written by DefinitionJSON, its keys reordered as jsonb reorders
// them, and parsed again.
func storedLike(t *testing.T, def *adapter.Tool) *adapter.Tool {
	t.Helper()
	raw, err := DefinitionJSON(def)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		t.Fatal(err)
	}
	// encoding/json writes map keys sorted, which is a different order
	// from both the authored one and DefinitionJSON's: what matters is
	// that the order changed.
	reordered, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ParseToolJSON(reordered)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// storedConnector returns the connector an install of a leaves behind.
func storedConnector(t *testing.T, a *adapter.Adapter, hash string) *Connector {
	t.Helper()
	c := &Connector{ID: "con_1", Instructions: a.Instructions, CatalogSlug: a.Metadata.Slug, CatalogHash: hash, Version: 1}
	tr, err := json.Marshal(a.Transport)
	if err != nil {
		t.Fatal(err)
	}
	au, err := json.Marshal(a.Auth)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(tr, &c.Transport); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(au, &c.Auth); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestPlanResyncOfFreshInstallIsEmpty re-syncs a simulated fresh install
// of every bundled adapter. Anything but an empty plan means re-sync
// would rewrite tools nobody changed, on every connector, forever.
func TestPlanResyncOfFreshInstallIsEmpty(t *testing.T) {
	t.Parallel()
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range cat.Index.Adapters {
		a, entry, err := cat.Bundled(e.Slug)
		if err != nil {
			t.Fatalf("%s: %v", e.Slug, err)
		}
		if got, err := adapter.ContentHash(a); err != nil || got != entry.ContentHash {
			t.Errorf("%s: index hash %s, adapter hashes to %s (%v)", e.Slug, entry.ContentHash, got, err)
		}
		c := storedConnector(t, a, entry.ContentHash)
		stored := make([]*Tool, 0, len(a.Tools))
		for i := range a.Tools {
			stored = append(stored, &Tool{ID: a.Tools[i].Name, Name: a.Tools[i].Name, Source: ToolSourceCatalog,
				Enabled: true, Definition: storedLike(t, &a.Tools[i])})
		}
		creds := map[string]bool{}
		for _, k := range a.Credentials.Keys {
			creds[k] = true
		}
		p, err := planResync(c, stored, creds, a, entry)
		if err != nil {
			t.Fatalf("%s: %v", e.Slug, err)
		}
		if p.Outdated() || !p.Empty() || len(p.Skipped) > 0 || len(p.NotApplied) > 0 {
			t.Errorf("%s: a fresh install plans a re-sync: add %v update %v remove %v skipped %v fields %v not applied %v",
				e.Slug, names(p.Add), p.Update, names(p.Remove), p.Skipped, p.Fields, p.NotApplied)
		}
	}
}

func names(ts []ResyncTool) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out
}

func TestPlanResync(t *testing.T) {
	t.Parallel()
	const bundledYAML = `apiVersion: supermcp.dev/v2
kind: Adapter
metadata:
  slug: example
  name: Example
instructions: Newer instructions.
transport:
  type: http
  baseUrl: https://api.example.com/v2
auth:
  type: bearer
  token: '{{env.API_KEY}}'
credentials:
  API_KEY:
    required: true
    secret: true
tools:
  - name: same
    description: Unchanged.
    operation: {method: GET, path: /same}
  - name: changed
    description: The new description.
    operation: {method: GET, path: /changed}
  - name: edited
    description: The catalog's newer text.
    operation: {method: GET, path: /edited}
  - name: clash
    description: The catalog's tool.
    operation: {method: GET, path: /clash}
  - name: legacy
    description: Unchanged, installed by an older replica.
    operation: {method: GET, path: /legacy}
  - name: legacy_changed
    description: Changed, installed by an older replica.
    operation: {method: POST, path: /legacy}
  - name: added
    description: New in this version.
    operation: {method: GET, path: /added}
`
	a, err := adapter.Parse([]byte(bundledYAML))
	if err != nil {
		t.Fatal(err)
	}
	def := func(name, desc, method, path string) *adapter.Tool {
		d, err := ParseToolJSON([]byte(`{"name":"` + name + `","description":"` + desc + `","operation":{"method":"` + method + `","path":"` + path + `"}}`))
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	edited := time.Now()
	tool := func(name, source string, editedAt *time.Time, d *adapter.Tool) *Tool {
		return &Tool{ID: "id_" + name, Name: name, Source: source, EditedAt: editedAt, Enabled: true, Definition: d}
	}
	stored := []*Tool{
		tool("changed", ToolSourceCatalog, nil, def("changed", "The old description.", "GET", "/changed")),
		tool("clash", ToolSourceCustom, nil, def("clash", "Made in the editor.", "GET", "/clash")),
		tool("edited", ToolSourceCatalog, &edited, def("edited", "Someone's own text.", "GET", "/edited")),
		tool("gone", ToolSourceCatalog, nil, def("gone", "Dropped from the adapter.", "GET", "/gone")),
		tool("gone_edited", ToolSourceCatalog, &edited, def("gone_edited", "Dropped, but edited.", "GET", "/gone")),
		tool("legacy", ToolSourceImport, nil, def("legacy", "Unchanged, installed by an older replica.", "GET", "/legacy")),
		tool("legacy_changed", ToolSourceImport, nil, def("legacy_changed", "Changed, installed by an older replica.", "GET", "/legacy")),
		tool("mine", ToolSourceCustom, nil, def("mine", "The organisation's own.", "GET", "/mine")),
		tool("same", ToolSourceCatalog, nil, def("same", "Unchanged.", "GET", "/same")),
	}
	c := &Connector{ID: "con_1", CatalogSlug: "example", CatalogHash: "old", Instructions: "Older instructions.",
		Transport: adapter.Transport{Type: adapter.TransportHTTP, BaseURL: "https://api.example.com/v1"},
		Auth:      adapter.Auth{Type: adapter.AuthBearer, Token: "{{env.API_KEY}}"}}

	p, err := planResync(c, stored, map[string]bool{}, a, adapter.IndexEntry{ContentHash: "new", PreviousHashes: []string{"old"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Outdated() {
		t.Error("the plan does not see the hashes differ")
	}
	if got := names(p.Add); !reflect.DeepEqual(got, []string{"added"}) {
		t.Errorf("add = %v, want [added]", got)
	}
	if got := names(p.Update); !reflect.DeepEqual(got, []string{"changed", "legacy_changed"}) {
		t.Errorf("update = %v, want [changed legacy_changed]", got)
	}
	if len(p.Update) == 2 {
		if got := p.Update[0].Changed; !reflect.DeepEqual(got, []string{"description"}) {
			t.Errorf("changed fields of changed = %v, want [description]", got)
		}
		if got := p.Update[1].Changed; !reflect.DeepEqual(got, []string{"operation"}) {
			t.Errorf("changed fields of legacy_changed = %v, want [operation]", got)
		}
	}
	if got := names(p.Remove); !reflect.DeepEqual(got, []string{"gone"}) {
		t.Errorf("remove = %v, want [gone]", got)
	}
	wantSkipped := []SkippedTool{
		{Name: "clash", ToolID: "id_clash", Reason: SkipCustom, Change: ChangeAdd},
		{Name: "edited", ToolID: "id_edited", Reason: SkipEdited, Change: ChangeUpdate},
		{Name: "gone_edited", ToolID: "id_gone_edited", Reason: SkipEdited, Change: ChangeRemove},
	}
	if !reflect.DeepEqual(p.Skipped, wantSkipped) {
		t.Errorf("skipped = %+v\nwant      %+v", p.Skipped, wantSkipped)
	}
	var fields []string
	for _, f := range p.Fields {
		fields = append(fields, f.Field)
	}
	if !reflect.DeepEqual(fields, []string{"instructions"}) {
		t.Errorf("fields = %v, want [instructions]", fields)
	}
	// The operator's transport stays; the difference is only reported.
	if len(p.NotApplied) != 1 || p.NotApplied[0].Field != "transport" {
		t.Errorf("not applied = %+v, want transport", p.NotApplied)
	}
	if got := names(p.Relabel); !reflect.DeepEqual(got, []string{"legacy", "legacy_changed"}) {
		t.Errorf("relabel = %v, want [legacy legacy_changed]", got)
	}
	if !reflect.DeepEqual(p.MissingCredentials, []string{"API_KEY"}) {
		t.Errorf("missing credentials = %v, want [API_KEY]", p.MissingCredentials)
	}
}
