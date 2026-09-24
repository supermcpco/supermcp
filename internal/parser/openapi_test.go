package parser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

func TestFromOpenAPI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		file  string
		opts  Options
		check func(t *testing.T, a *adapter.Adapter, findings []ImportFinding)
	}{
		{
			name: "openapi 3.0",
			file: "petstore-3.0.json",
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				if HasBlockers(findings) {
					t.Fatalf("unexpected blockers: %v", findings)
				}
				if a.Transport.Type != adapter.TransportHTTP || a.Transport.BaseURL != "https://api.petstore.example.com/v1" {
					t.Errorf("transport = %+v", a.Transport)
				}
				if a.Metadata.Slug != "pet-store" {
					t.Errorf("slug = %q", a.Metadata.Slug)
				}
				if a.Auth.Type != adapter.AuthBearer || a.Auth.Token != "{{env.API_TOKEN}}" {
					t.Errorf("auth = %+v", a.Auth)
				}
				cred, ok := a.Credentials.Get("API_TOKEN")
				if !ok || !cred.Required || !cred.Secret {
					t.Errorf("credential API_TOKEN = %+v, ok=%v", cred, ok)
				}
				wantTools := []string{"pet_store_list_pets", "pet_store_create_pet", "pet_store_get_pet", "pet_store_delete_pet"}
				if got := toolNames(a); !equal(got, wantTools) {
					t.Fatalf("tools = %v, want %v", got, wantTools)
				}

				list := toolNamed(t, a, "pet_store_list_pets")
				if list.Operation.Method != "GET" || list.Operation.Path != "/pets" {
					t.Errorf("list operation = %+v", list.Operation)
				}
				if list.Annotations == nil || list.Annotations.ReadOnlyHint == nil || !*list.Annotations.ReadOnlyHint {
					t.Errorf("GET should be read-only, got %+v", list.Annotations)
				}
				if got := nodeJSON(t, list.Operation.Query); got != `{"limit":"{{params.limit}}"}` {
					t.Errorf("query = %s", got)
				}
				if got, _ := list.Operation.Headers.Get("X-Request-Id"); got != "{{params.X_Request_Id}}" {
					t.Errorf("header mapping = %q", got)
				}
				if got, _ := list.Operation.Headers.Get("Cookie"); got != "session={{params.session}}" {
					t.Errorf("cookie mapping = %q", got)
				}

				get := toolNamed(t, a, "pet_store_get_pet")
				if get.Operation.Path != "/pets/{{params.petId}}" {
					t.Errorf("path = %q", get.Operation.Path)
				}

				del := toolNamed(t, a, "pet_store_delete_pet")
				if del.Annotations == nil || del.Annotations.DestructiveHint == nil || !*del.Annotations.DestructiveHint {
					t.Errorf("DELETE should be destructive, got %+v", del.Annotations)
				}
				// The path parameter came in through a components $ref.
				if del.Operation.Path != "/pets/{{params.petId}}" {
					t.Errorf("path = %q", del.Operation.Path)
				}

				create := toolNamed(t, a, "pet_store_create_pet")
				wantBody := map[string]any{"name": "{{params.name}}", "tag": "{{params.tag}}", "owner": "{{params.owner}}"}
				if got := nodeMap(t, create.Operation.Body.Value); !reflect.DeepEqual(got, wantBody) {
					t.Errorf("body = %v, want %v", got, wantBody)
				}
				if create.Operation.Body.Encoding != "json" {
					t.Errorf("encoding = %q", create.Operation.Body.Encoding)
				}
				in := inputMap(t, create)
				if in["required"].([]any)[0] != "name" {
					t.Errorf("required = %v", in["required"])
				}
				owner := in["properties"].(map[string]any)["owner"].(map[string]any)
				if owner["type"] != "object" {
					t.Errorf("owner schema was not resolved: %v", owner)
				}
			},
		},
		{
			name: "openapi 3.1",
			file: "library-3.1.json",
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				if HasBlockers(findings) {
					t.Fatalf("unexpected blockers: %v", findings)
				}
				if a.Auth.Type != adapter.AuthOAuth2 || a.Auth.Grant != "client_credentials" {
					t.Fatalf("auth = %+v", a.Auth)
				}
				// The token URL was written relative to the server.
				if a.Auth.TokenURL != "https://library.example.com/oauth/token" {
					t.Errorf("tokenUrl = %q", a.Auth.TokenURL)
				}
				if !equal(a.Auth.Scopes, []string{"loans:read", "loans:write"}) {
					t.Errorf("scopes = %v", a.Auth.Scopes)
				}
				search := toolNamed(t, a, "lending_library_search_books")
				props := inputMap(t, search)["properties"].(map[string]any)
				if q := props["q"].(map[string]any); q["type"] != "string" {
					t.Errorf("3.1 type list was not narrowed: %v", q)
				}
				if !hasFinding(findings, Info, "type list") {
					t.Errorf("narrowing a type list should be reported: %v", findings)
				}
				if !hasFinding(findings, Info, "webhooks") {
					t.Errorf("webhooks should be reported as skipped: %v", findings)
				}
				extend := toolNamed(t, a, "lending_library_extend_loan")
				wantBody := map[string]any{"days": "{{params.days}}", "note": "{{params.note}}"}
				if got := nodeMap(t, extend.Operation.Body.Value); !reflect.DeepEqual(got, wantBody) {
					t.Errorf("body = %v, want %v", got, wantBody)
				}
				if got := inputMap(t, extend)["required"].([]any); !equal(strs(got), []string{"loanId", "days"}) {
					t.Errorf("required = %v", got)
				}
				head := toolNamed(t, a, "lending_library_loan_exists")
				if head.Annotations == nil || head.Annotations.ReadOnlyHint == nil || !*head.Annotations.ReadOnlyHint {
					t.Errorf("HEAD should be read-only, got %+v", head.Annotations)
				}
			},
		},
		{
			name: "no operation ids",
			file: "no-operation-ids.json",
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				want := []string{
					"weather_service_get_stations",
					"weather_service_get_stations_by_station_id_readings",
					"weather_service_post_stations_by_station_id_readings",
				}
				if got := toolNames(a); !equal(got, want) {
					t.Fatalf("tools = %v, want %v", got, want)
				}
				derived := 0
				for _, f := range findings {
					if strings.Contains(f.Message, "no operationId") {
						derived++
						if f.Operation == "" {
							t.Errorf("finding does not name its operation: %+v", f)
						}
					}
				}
				if derived != 3 {
					t.Errorf("want a finding per unnamed operation, got %d: %v", derived, findings)
				}
				// The POST does not redeclare the path parameter the GET did.
				if !hasFinding(findings, Review, "path placeholder {stationId}") {
					t.Errorf("an undeclared path placeholder should be reported: %v", findings)
				}
			},
		},
		{
			name: "reference cycle",
			file: "ref-cycle.json",
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				if !hasFinding(findings, Review, "is a cycle") {
					t.Fatalf("a $ref cycle should be reported: %v", findings)
				}
				props := inputMap(t, toolNamed(t, a, "comment_threads_post_comment"))["properties"].(map[string]any)
				if props["body"].(map[string]any)["type"] != "string" {
					t.Errorf("the non-recursive fields should survive: %v", props)
				}
				if len(props["parent"].(map[string]any)) != 0 {
					t.Errorf("the recursive field should be cut, got %v", props["parent"])
				}
			},
		},
		{
			name: "external reference",
			file: "external-ref.json",
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				if !hasFinding(findings, Review, "https://schemas.example.com/address.json") {
					t.Fatalf("an external $ref should be reported: %v", findings)
				}
				if !hasFinding(findings, Review, "not fetched") {
					t.Errorf("the finding should say the reference was not fetched: %v", findings)
				}
				props := inputMap(t, toolNamed(t, a, "shipping_create_shipment"))["properties"].(map[string]any)
				if len(props["destination"].(map[string]any)) != 0 {
					t.Errorf("an unresolved reference should leave an empty schema, got %v", props["destination"])
				}
			},
		},
		{
			name: "unsupported security scheme",
			file: "unsupported-security.json",
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				if a.Auth.Type != adapter.AuthNone {
					t.Fatalf("auth = %+v, want none rather than a wrong guess", a.Auth)
				}
				if a.Credentials.Len() != 0 {
					t.Errorf("no credentials should be declared, got %v", a.Credentials.Keys)
				}
				if !hasFinding(findings, Review, "openIdConnect") {
					t.Errorf("openIdConnect should be reported: %v", findings)
				}
				if !hasFinding(findings, Review, `puts its API key in "cookie"`) {
					t.Errorf("an apiKey in a cookie should be reported: %v", findings)
				}
			},
		},
		{
			name: "several servers",
			file: "multi-server.json",
			check: func(t *testing.T, _ *adapter.Adapter, findings []ImportFinding) {
				if !HasBlockers(findings) {
					t.Fatalf("several servers should block the import: %v", findings)
				}
				if !hasFinding(findings, Blocker, "sandbox.ledger.example.com") {
					t.Errorf("the finding should list the candidates: %v", findings)
				}
			},
		},
		{
			name: "several servers, one chosen",
			file: "multi-server.json",
			opts: Options{ServerURL: "https://sandbox.ledger.example.com"},
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				if HasBlockers(findings) {
					t.Fatalf("a chosen server should settle it: %v", findings)
				}
				if a.Transport.BaseURL != "https://sandbox.ledger.example.com" {
					t.Errorf("baseUrl = %q", a.Transport.BaseURL)
				}
				if a.Auth.Type != adapter.AuthAPIKey || a.Auth.In != "header" || a.Auth.Name != "X-Api-Key" || a.Auth.Value != "{{env.API_KEY}}" {
					t.Errorf("auth = %+v", a.Auth)
				}
			},
		},
		{
			name: "allOf body",
			file: "allof-body.json",
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				if HasBlockers(findings) {
					t.Fatalf("unexpected blockers: %v", findings)
				}
				if a.Auth.Type != adapter.AuthBasic || a.Auth.Username != "{{env.API_USERNAME}}" || a.Auth.Password != "{{env.API_PASSWORD}}" {
					t.Errorf("auth = %+v", a.Auth)
				}
				create := toolNamed(t, a, "invoicing_create_invoice")
				in := inputMap(t, create)
				props := in["properties"].(map[string]any)
				for _, key := range []string{"reference", "currency", "customerId", "dueDate"} {
					if _, ok := props[key]; !ok {
						t.Errorf("allOf member %q is missing from the input: %v", key, props)
					}
				}
				if got := strs(in["required"].([]any)); !equal(got, []string{"reference", "customerId"}) {
					t.Errorf("required = %v", got)
				}
				if got := nodeJSON(t, create.Operation.Body.Value); !strings.Contains(got, `"currency":"{{params.currency}}"`) {
					t.Errorf("body = %s", got)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, findings, err := FromOpenAPI(fixture(t, tc.file), tc.opts)
			if err != nil {
				t.Fatalf("FromOpenAPI: %v", err)
			}
			for _, f := range findings {
				if f.Level != Info && f.Level != Review && f.Level != Blocker {
					t.Errorf("finding has an unknown level: %+v", f)
				}
				if f.Path == "" || f.Message == "" {
					t.Errorf("finding is incomplete: %+v", f)
				}
			}
			// The validator is the contract; only a blocked import may fail it.
			if !HasBlockers(findings) {
				mustValidate(t, a)
			}
			tc.check(t, a, findings)
		})
	}
}

// TestFromOpenAPIRefuses covers the documents the importer will not touch.
func TestFromOpenAPIRefuses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		doc  string
		opts Options
		want string
	}{
		{name: "swagger 2", doc: `{"swagger":"2.0","info":{"title":"Old"}}`, want: "swagger 2.0 is not supported"},
		{name: "openapi 4", doc: `{"openapi":"4.0.0","info":{"title":"Next"}}`, want: `openapi version "4.0.0" is not supported`},
		{name: "no version", doc: `{"info":{"title":"Anon"}}`, want: "no openapi version"},
		{name: "no operations", doc: `{"openapi":"3.0.0","info":{"title":"Empty"},"servers":[{"url":"https://e.example.com"}],"paths":{}}`, want: "no operations"},
		{name: "not json or yaml", doc: "{not json at all", want: "parse json"},
		{
			name: "yaml anchors",
			doc:  "openapi: 3.0.0\ninfo:\n  title: Bomb\n  x: &a [1,1,1]\n  y: *a\npaths: {}\n",
			want: "anchors and aliases",
		},
		{
			name: "oversized",
			doc:  `{"openapi":"3.0.0"}`,
			opts: Options{MaxBytes: 4},
			want: "over the 4 byte limit",
		},
		{
			name: "unknown region",
			doc:  `{"openapi":"3.0.0"}`,
			opts: Options{Region: "mars"},
			want: `region "mars" is not a known region`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := FromOpenAPI([]byte(tc.doc), tc.opts)
			if err == nil {
				t.Fatalf("want an error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestFromOpenAPIYAML checks the other half of the world's OpenAPI
// documents, which are not JSON.
func TestFromOpenAPIYAML(t *testing.T) {
	t.Parallel()
	doc := `
openapi: 3.0.3
info:
  title: Tasks
  description: A short task list service, kept in YAML the way most documents are.
servers:
  - url: https://tasks.example.com
paths:
  /tasks:
    get:
      operationId: listTasks
      summary: List every task, open or closed, in the order they were created
      responses:
        "200":
          description: ok
`
	a, findings, err := FromOpenAPI([]byte(doc), Options{})
	if err != nil {
		t.Fatalf("FromOpenAPI: %v", err)
	}
	if HasBlockers(findings) {
		t.Fatalf("unexpected blockers: %v", findings)
	}
	mustValidate(t, a)
	if got := toolNames(a); !equal(got, []string{"tasks_list_tasks"}) {
		t.Errorf("tools = %v", got)
	}
}

// TestOperationCap proves the bound is enforced rather than documented.
func TestOperationCap(t *testing.T) {
	t.Parallel()
	a, findings, err := FromOpenAPI(fixture(t, "petstore-3.0.json"), Options{MaxOperations: 2})
	if err != nil {
		t.Fatalf("FromOpenAPI: %v", err)
	}
	if len(a.Tools) != 2 {
		t.Errorf("tools = %d, want the cap of 2", len(a.Tools))
	}
	if !hasFinding(findings, Blocker, "more than 2 operations") {
		t.Errorf("hitting the cap should block the import: %v", findings)
	}
}

// TestDeterministic is the reason tool names come from operationIds and
// paths are walked in document order: two imports of one document must
// produce the same connector.
func TestDeterministic(t *testing.T) {
	t.Parallel()
	doc := fixture(t, "petstore-3.0.json")
	first, firstFindings, err := FromOpenAPI(doc, Options{})
	if err != nil {
		t.Fatalf("FromOpenAPI: %v", err)
	}
	for i := 0; i < 5; i++ {
		next, nextFindings, err := FromOpenAPI(doc, Options{})
		if err != nil {
			t.Fatalf("FromOpenAPI: %v", err)
		}
		if a, b := marshal(t, first), marshal(t, next); a != b {
			t.Fatalf("import %d differs:\n%s\n---\n%s", i, a, b)
		}
		if len(firstFindings) != len(nextFindings) {
			t.Fatalf("import %d produced %d findings, first produced %d", i, len(nextFindings), len(firstFindings))
		}
	}
}

// --- helpers ---------------------------------------------------------------

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

// mustValidate fails on a validator error. Warnings are expected: an
// imported document rarely carries 800 characters of instructions or a
// healthcheck.
func mustValidate(t *testing.T, a *adapter.Adapter) {
	t.Helper()
	for _, issue := range adapter.Validate(&adapter.File{Adapter: a}) {
		if issue.Severity == adapter.SeverityError {
			t.Errorf("validator: %s: %s", issue.Rule, issue.Message)
		}
	}
}

func toolNames(a *adapter.Adapter) []string {
	out := make([]string, 0, len(a.Tools))
	for _, tool := range a.Tools {
		out = append(out, tool.Name)
	}
	return out
}

func toolNamed(t *testing.T, a *adapter.Adapter, name string) *adapter.Tool {
	t.Helper()
	for i := range a.Tools {
		if a.Tools[i].Name == name {
			return &a.Tools[i]
		}
	}
	t.Fatalf("no tool %q in %v", name, toolNames(a))
	return nil
}

func nodeJSON(t *testing.T, n *adapter.Node) string {
	t.Helper()
	if n == nil {
		return ""
	}
	raw, err := n.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal node: %v", err)
	}
	return string(raw)
}

func inputMap(t *testing.T, tool *adapter.Tool) map[string]any {
	t.Helper()
	return nodeMap(t, tool.Input)
}

// nodeMap decodes a node for comparison. Key order is not asserted here:
// the node keeps the document's order, but JSON objects do not.
func nodeMap(t *testing.T, n *adapter.Node) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(nodeJSON(t, n)), &out); err != nil {
		t.Fatalf("decode node: %v", err)
	}
	return out
}

func marshal(t *testing.T, a *adapter.Adapter) string {
	t.Helper()
	raw, err := adapter.Marshal(a)
	if err != nil {
		t.Fatalf("marshal adapter: %v", err)
	}
	return string(raw)
}

func hasFinding(findings []ImportFinding, level Level, substr string) bool {
	for _, f := range findings {
		if f.Level == level && strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func strs(list []any) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
