package parser

import (
	"reflect"
	"strings"
	"testing"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

func TestFromPostman(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		file  string
		opts  Options
		check func(t *testing.T, a *adapter.Adapter, findings []ImportFinding)
	}{
		{
			name: "a whole collection",
			file: "acme-billing.postman_collection.json",
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				if HasBlockers(findings) {
					t.Fatalf("unexpected blockers: %v", findings)
				}
				// {{baseUrl}} is a collection variable with a literal value,
				// so it settles the upstream rather than becoming a parameter.
				if a.Transport.Type != adapter.TransportHTTP || a.Transport.BaseURL != "https://api.acme-billing.example.com" {
					t.Errorf("transport = %+v", a.Transport)
				}
				if a.Metadata.Slug != "acme-billing" || a.Metadata.Name != "Acme Billing" {
					t.Errorf("metadata = %+v", a.Metadata)
				}

				// The collection's bearer auth reads {{apiToken}}, which is
				// marked secret, so it is a credential and its literal value
				// is nowhere in the adapter.
				if a.Auth.Type != adapter.AuthBearer || a.Auth.Token != "{{env.API_TOKEN}}" {
					t.Errorf("auth = %+v", a.Auth)
				}
				if cred, ok := a.Credentials.Get("API_TOKEN"); !ok || !cred.Required || !cred.Secret {
					t.Errorf("credential API_TOKEN = %+v, ok = %v", cred, ok)
				}
				if !hasFinding(findings, Review, `variable "apiToken" is marked secret`) {
					t.Errorf("moving the token out should be reported: %v", findings)
				}
				if body := marshal(t, a); strings.Contains(body, "sk_live_") {
					t.Fatal("the collection's live token was written into the adapter")
				}

				// Folders prefix the tool names, so "Create" in two folders
				// would still be two tools.
				want := []string{
					"acme_billing_customers_list_customers",
					"acme_billing_customers_get_customer",
					"acme_billing_customers_create_customer",
					"acme_billing_customers_delete_customer",
					"acme_billing_invoices_create_invoice",
					"acme_billing_invoices_attach_receipt",
					"acme_billing_ping",
				}
				if got := toolNames(a); !equal(got, want) {
					t.Fatalf("tools = %v, want %v", got, want)
				}

				list := toolNamed(t, a, "acme_billing_customers_list_customers")
				if list.Operation.Method != "GET" || list.Operation.Path != "/v1/customers" {
					t.Errorf("list operation = %+v", list.Operation)
				}
				// A disabled query parameter is one the author switched off.
				wantQuery := map[string]any{"limit": "{{params.limit}}", "email": "{{params.searchEmail}}"}
				if got := nodeMap(t, list.Operation.Query); !reflect.DeepEqual(got, wantQuery) {
					t.Errorf("query = %v, want %v", got, wantQuery)
				}
				if _, ok := list.Operation.Headers.Get("X-Acme-Trace"); ok {
					t.Error("a disabled header was imported")
				}
				props := inputMap(t, list)["properties"].(map[string]any)
				if limit := props["limit"].(map[string]any); limit["default"] != "20" {
					t.Errorf("the saved value should become the default, got %v", limit)
				}
				// The saved example gives the tool an output schema and a
				// sentence about what comes back.
				if list.Output == nil {
					t.Fatal("the saved example should have produced an output schema")
				}
				out := nodeMap(t, list.Output)
				data := out["properties"].(map[string]any)["data"].(map[string]any)
				if data["type"] != "array" {
					t.Errorf("output schema = %v", out)
				}
				if !strings.Contains(list.Description, "cus_00001") {
					t.Errorf("the example should be quoted in the description: %q", list.Description)
				}

				get := toolNamed(t, a, "acme_billing_customers_get_customer")
				if get.Operation.Path != "/v1/customers/{{params.customerId}}" {
					t.Errorf("path = %q", get.Operation.Path)
				}
				if get.Annotations == nil || get.Annotations.ReadOnlyHint == nil || !*get.Annotations.ReadOnlyHint {
					t.Errorf("a GET should read only, got %+v", get.Annotations)
				}

				create := toolNamed(t, a, "acme_billing_customers_create_customer")
				wantBody := map[string]any{
					"email":   "{{params.customerEmail}}",
					"name":    "{{params.name}}",
					"balance": "{{params.balance}}",
					// A nested object keeps the shape the collection recorded;
					// only the variable inside it becomes a parameter.
					"metadata": map[string]any{"plan": "pro", "source": "{{params.signupSource}}"},
				}
				if got := nodeMap(t, create.Operation.Body.Value); !reflect.DeepEqual(got, wantBody) {
					t.Errorf("body = %v, want %v", got, wantBody)
				}
				if create.Operation.Body.Encoding != "json" {
					t.Errorf("encoding = %q", create.Operation.Body.Encoding)
				}
				required := strs(inputMap(t, create)["required"].([]any))
				if !equal(required, []string{"customerEmail", "signupSource"}) {
					t.Errorf("required = %v; only the fields the author parameterised are obligatory", required)
				}
				if !hasFinding(findings, Review, "does not run scripts") {
					t.Errorf("the pre-request script should be reported: %v", findings)
				}

				del := toolNamed(t, a, "acme_billing_customers_delete_customer")
				if del.Annotations == nil || del.Annotations.DestructiveHint == nil || !*del.Annotations.DestructiveHint {
					t.Errorf("a DELETE should be destructive, got %+v", del.Annotations)
				}

				invoice := toolNamed(t, a, "acme_billing_invoices_create_invoice")
				if invoice.Operation.Body.Encoding != "form" {
					t.Errorf("urlencoded should map to form, got %q", invoice.Operation.Body.Encoding)
				}
				wantForm := map[string]any{"customer": "{{params.customerId}}", "currency": "{{params.currency}}"}
				if got := nodeMap(t, invoice.Operation.Body.Value); !reflect.DeepEqual(got, wantForm) {
					t.Errorf("form body = %v, want %v; a disabled field should be left out", got, wantForm)
				}

				receipt := toolNamed(t, a, "acme_billing_invoices_attach_receipt")
				if receipt.Operation.Body.Encoding != "multipart" {
					t.Errorf("formdata should map to multipart, got %q", receipt.Operation.Body.Encoding)
				}
				if !hasFinding(findings, Review, "file picked from disk") {
					t.Errorf("the file part should be reported: %v", findings)
				}

				// A key written straight into a header is still a key.
				ping := toolNamed(t, a, "acme_billing_ping")
				if got, _ := ping.Operation.Headers.Get("X-Api-Key"); got != "{{env.X_API_KEY}}" {
					t.Errorf("X-Api-Key = %q", got)
				}
				if _, ok := a.Credentials.Get("X_API_KEY"); !ok {
					t.Errorf("credentials = %v", a.Credentials.Keys)
				}
				if !hasFinding(findings, Review, "looks like a credential") {
					t.Errorf("moving the header's key out should be reported: %v", findings)
				}
			},
		},
		{
			name: "two hosts is a decision, not a guess",
			file: "two-hosts.postman_collection.json",
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				if !HasBlockers(findings) {
					t.Fatal("a collection that calls two hosts should block")
				}
				if !hasFinding(findings, Blocker, "calls 2 hosts") {
					t.Errorf("findings = %v", findings)
				}
				// The first still fills the preview, so the rest is readable.
				if a.Transport.BaseURL != "https://api.first.example.com" {
					t.Errorf("baseUrl = %q", a.Transport.BaseURL)
				}
				// A token written into an Authorization header becomes the
				// connector's auth rather than a literal on one tool.
				if a.Auth.Type != adapter.AuthBearer || a.Auth.Token != "{{env.API_TOKEN}}" {
					t.Errorf("auth = %+v", a.Auth)
				}
				if body := marshal(t, a); strings.Contains(body, "ghp_") {
					t.Fatal("the pasted GitHub token was written into the adapter")
				}
				if !hasFinding(findings, Review, "but the connector calls") {
					t.Errorf("the second host's requests should be flagged: %v", findings)
				}
			},
		},
		{
			name: "the base URL can be supplied",
			file: "two-hosts.postman_collection.json",
			opts: Options{ServerURL: "https://api.first.example.com", Slug: "first"},
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				if HasBlockers(findings) {
					t.Fatalf("supplying the base URL should settle it: %v", findings)
				}
				if a.Metadata.Slug != "first" || !strings.HasPrefix(a.Tools[0].Name, "first_") {
					t.Errorf("slug = %q, first tool = %q", a.Metadata.Slug, a.Tools[0].Name)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, findings, err := FromPostman(fixture(t, tc.file), tc.opts)
			if err != nil {
				t.Fatalf("FromPostman: %v", err)
			}
			mustValidate(t, a)
			tc.check(t, a, findings)
		})
	}
}

func TestFromPostmanRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{name: "not a collection", doc: `{"paths":{}}`, want: "not a Postman collection"},
		{name: "not JSON at all", doc: `hello`, want: "not a Postman collection"},
		{name: "no requests", doc: `{"info":{"name":"Empty","schema":"v2.1.0"},"item":[]}`, want: "no request"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := FromPostman([]byte(tc.doc), Options{}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want something about %q", err, tc.want)
			}
		})
	}
}

// A second import of one collection must produce the same connector, or
// re-importing renames tools and every role assignment that referred to
// them stops matching.
func TestFromPostmanIsDeterministic(t *testing.T) {
	t.Parallel()

	doc := fixture(t, "acme-billing.postman_collection.json")
	first, firstFindings, err := FromPostman(doc, Options{})
	if err != nil {
		t.Fatalf("FromPostman: %v", err)
	}
	for i := 0; i < 5; i++ {
		next, nextFindings, err := FromPostman(doc, Options{})
		if err != nil {
			t.Fatalf("FromPostman: %v", err)
		}
		if a, b := marshal(t, first), marshal(t, next); a != b {
			t.Fatalf("import %d differs:\n%s\n---\n%s", i, a, b)
		}
		if len(firstFindings) != len(nextFindings) {
			t.Fatalf("import %d produced %d findings, the first produced %d", i, len(nextFindings), len(firstFindings))
		}
	}
}

// A collection variable used in two places is one thing the caller
// supplies, not two that have to be kept in step.
func TestFromPostmanOneVariableIsOneParameter(t *testing.T) {
	t.Parallel()

	collection := `{
	  "info": {"name": "Shared", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
	  "item": [{
	    "name": "Rename thing",
	    "request": {
	      "method": "PUT",
	      "url": {"raw": "https://api.example.com/things/{{thingId}}", "host": ["api","example","com"], "path": ["things","{{thingId}}"]},
	      "body": {"mode": "raw", "options": {"raw": {"language": "json"}},
	               "raw": "{\"id\": \"{{thingId}}\", \"name\": \"{{newName}}\"}"}
	    }
	  }]
	}`

	a, findings, err := FromPostman([]byte(collection), Options{})
	if err != nil {
		t.Fatalf("FromPostman: %v", err)
	}
	mustValidate(t, a)
	if HasBlockers(findings) {
		t.Fatalf("unexpected blockers: %v", findings)
	}
	tool := a.Tools[0]
	if tool.Operation.Path != "/things/{{params.thingId}}" {
		t.Errorf("path = %q", tool.Operation.Path)
	}
	want := map[string]any{"id": "{{params.thingId}}", "name": "{{params.newName}}"}
	if got := nodeMap(t, tool.Operation.Body.Value); !reflect.DeepEqual(got, want) {
		t.Errorf("body = %v, want %v", got, want)
	}
	props := inputMap(t, &tool)["properties"].(map[string]any)
	if len(props) != 2 {
		t.Fatalf("properties = %v; one variable in two places is one parameter", props)
	}
}
