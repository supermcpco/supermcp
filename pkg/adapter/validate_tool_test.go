package adapter_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/supermcpco/supermcp/adapters"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

func mustNode(t *testing.T, js string) *adapter.Node {
	t.Helper()
	n, err := adapter.NodeFromJSON([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

const longDescription = "Lists the invoices of one customer, newest first, with their totals and status."

func TestValidateTool(t *testing.T) {
	t.Parallel()
	obj := `{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`
	type want struct{ rule, field string }
	cases := []struct {
		name      string
		transport adapter.TransportType
		tool      func(t *testing.T) *adapter.Tool
		want      []want
	}{
		{
			name:      "valid http tool",
			transport: adapter.TransportHTTP,
			tool: func(t *testing.T) *adapter.Tool {
				return &adapter.Tool{Name: "list_invoices", Description: longDescription, Input: mustNode(t, obj),
					Operation: adapter.Operation{Method: "GET", Path: "/invoices/{{params.id}}"}}
			},
		},
		{
			name:      "bad name, short description, no input",
			transport: adapter.TransportHTTP,
			tool: func(t *testing.T) *adapter.Tool {
				return &adapter.Tool{Name: "List-Invoices", Description: "short", Operation: adapter.Operation{Method: "GET"}}
			},
			want: []want{{"tool-name-format", "name"}, {"description-min-60", "description"}, {"input-required", "input"}},
		},
		{
			name:      "a name in supermcp's own namespace",
			transport: adapter.TransportHTTP,
			tool: func(t *testing.T) *adapter.Tool {
				return &adapter.Tool{Name: "supermcp_approval_status", Description: longDescription, Input: mustNode(t, obj),
					Operation: adapter.Operation{Method: "GET", Path: "/invoices/{{params.id}}"}}
			},
			want: []want{{"tool-name-reserved", "name"}},
		},
		{
			name:      "unknown param and bad method",
			transport: adapter.TransportHTTP,
			tool: func(t *testing.T) *adapter.Tool {
				return &adapter.Tool{Name: "get_x", Description: longDescription, Input: mustNode(t, obj),
					Operation: adapter.Operation{Method: "FETCH", Path: "/x/{{params.nope}}"}}
			},
			want: []want{{"placeholder-unknown", "operation.path"}, {"operation-method", "operation.method"}},
		},
		{
			name:      "placeholder in a header and in the body",
			transport: adapter.TransportHTTP,
			tool: func(t *testing.T) *adapter.Tool {
				return &adapter.Tool{Name: "post_x", Description: longDescription, Input: mustNode(t, obj),
					Operation: adapter.Operation{Method: "POST",
						Headers: adapter.OrderedMap[string]{Keys: []string{"X-Id"}, Values: map[string]string{"X-Id": "{{bogus.id}}"}},
						Body:    &adapter.Body{Encoding: "xml", Value: mustNode(t, `{"a":"{{params.missing}}"}`)}}}
			},
			want: []want{{"placeholder-namespace", "operation.headers.X-Id"}, {"placeholder-unknown", "operation.body.value"},
				{"operation-body-encoding", "operation.body.encoding"}},
		},
		{
			name:      "graphql without kind or document",
			transport: adapter.TransportGraphQL,
			tool: func(t *testing.T) *adapter.Tool {
				return &adapter.Tool{Name: "q", Description: longDescription, Input: mustNode(t, obj)}
			},
			want: []want{{"operation-kind", "operation.kind"}, {"operation-document", "operation.document"}},
		},
		{
			name:      "database write not marked destructive",
			transport: adapter.TransportDatabase,
			tool: func(t *testing.T) *adapter.Tool {
				return &adapter.Tool{Name: "wipe", Description: longDescription, Input: mustNode(t, obj),
					Operation: adapter.Operation{Kind: "sql", Statement: "DELETE FROM t WHERE id = {{params.id}}"}}
			},
			want: []want{{"sql-readonly", "operation.statement"}},
		},
		{
			name:      "static without value",
			transport: adapter.TransportHTTP,
			tool: func(t *testing.T) *adapter.Tool {
				return &adapter.Tool{Name: "s", Description: longDescription, Input: mustNode(t, obj), Operation: adapter.Operation{Kind: "static"}}
			},
			want: []want{{"operation-static", "operation.value"}},
		},
		{
			name:      "bad transform",
			transport: adapter.TransportHTTP,
			tool: func(t *testing.T) *adapter.Tool {
				return &adapter.Tool{Name: "g", Description: longDescription, Input: mustNode(t, obj), Operation: adapter.Operation{Method: "GET"},
					Response: &adapter.Response{Transform: &adapter.Transform{JMESPath: "[[["}}}
			},
			want: []want{{"jmespath-parses", "response.transform.jmespath"}},
		},
		{
			name:      "mcp without tool",
			transport: adapter.TransportMCP,
			tool: func(t *testing.T) *adapter.Tool {
				return &adapter.Tool{Name: "m", Description: longDescription, Input: mustNode(t, obj)}
			},
			want: []want{{"operation-tool", "operation.tool"}},
		},
		{
			name:      "env placeholders are not checked here",
			transport: adapter.TransportHTTP,
			tool: func(t *testing.T) *adapter.Tool {
				return &adapter.Tool{Name: "g", Description: longDescription, Input: mustNode(t, obj),
					Operation: adapter.Operation{Method: "GET", Path: "/x?key={{env.UNKNOWN}}"}}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			issues := adapter.ValidateTool(tc.tool(t), tc.transport)
			got := make([]want, 0, len(issues))
			for _, i := range issues {
				if i.File != "" {
					t.Errorf("issue has a file: %+v", i)
				}
				got = append(got, want{i.Rule, i.Field})
			}
			if len(tc.want) == 0 && len(got) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("issues = %v, want %v\n%+v", got, tc.want, issues)
			}
		})
	}
}

func TestToolPlaceholderEnv(t *testing.T) {
	t.Parallel()
	tl := &adapter.Tool{Operation: adapter.Operation{
		Path:    "/x/{{env.B}}?k={{ env.A}}",
		Headers: adapter.OrderedMap[string]{Keys: []string{"H"}, Values: map[string]string{"H": "{{env.B}} {{env.C | urlencode}}"}},
		Query:   mustNode(t, `{"q":"{{params.x}}","k":"{{env.D}}"}`),
	}}
	got := adapter.ToolPlaceholderEnv(tl)
	want := []string{"B", "A", "C", "D"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ToolPlaceholderEnv = %v, want %v", got, want)
	}
}

// TestValidateToolMatchesValidate checks that ValidateTool reports, for
// every catalog tool and for broken variants of them, exactly the per-tool
// issues Validate reports for that tool inside its adapter. It guards the
// extraction of the per-tool rules from Validate.
func TestValidateToolMatchesValidate(t *testing.T) {
	t.Parallel()
	files, err := adapter.LoadFS(adapters.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no catalog adapters")
	}
	// Rules Validate adds that need the whole adapter.
	adapterOnly := map[string]bool{"tool-name-unique": true, "tool-name-prefix": true}
	for _, f := range files {
		for variant := 0; variant < 2; variant++ {
			a := *f.Adapter
			a.Tools = append([]adapter.Tool(nil), a.Tools...)
			if variant == 1 {
				for i := range a.Tools {
					breakTool(&a.Tools[i], i)
				}
			}
			allow := map[string]bool{}
			if a.Metadata.Lint != nil {
				for _, r := range a.Metadata.Lint.Allow {
					allow[r] = true
				}
			}
			all := adapter.Validate(&adapter.File{Dir: f.Dir, Region: f.Region, Adapter: &a})
			for i := range a.Tools {
				tl := &a.Tools[i]
				if tl.Name == "" {
					continue
				}
				prefix := fmt.Sprintf("tools[%d] %s: ", i, tl.Name)
				var fromValidate []string
				for _, is := range all {
					if strings.HasPrefix(is.Message, prefix) && !adapterOnly[is.Rule] {
						fromValidate = append(fromValidate, is.Rule+"|"+is.Field+"|"+strings.TrimPrefix(is.Message, prefix))
					}
				}
				var fromTool []string
				for _, is := range adapter.ValidateTool(tl, a.Transport.Type) {
					if is.Severity == adapter.SeverityWarning && allow[is.Rule] {
						continue
					}
					fromTool = append(fromTool, is.Rule+"|"+is.Field+"|"+strings.TrimPrefix(is.Message, tl.Name+": "))
				}
				if !reflect.DeepEqual(fromValidate, fromTool) {
					t.Errorf("%s variant %d tool %s:\nValidate:     %v\nValidateTool: %v", f.Dir, variant, tl.Name, fromValidate, fromTool)
				}
			}
		}
	}
}

// breakTool makes one of several per-tool rules fire, chosen by i.
func breakTool(tl *adapter.Tool, i int) {
	switch i % 5 {
	case 0:
		tl.Name += "X"
		tl.Input = nil
	case 1:
		tl.Operation.Method = "FETCH"
		tl.Operation.Path = "/x/{{params.nope}}/{{bogus.x}}/{{"
		tl.Operation.Kind = "weird"
		tl.Operation.Document = ""
		tl.Operation.Statement = "DELETE FROM x"
		tl.Operation.Tool = ""
	case 2:
		tl.Response = &adapter.Response{Transform: &adapter.Transform{JMESPath: "[[["}}
		tl.Description = "short"
		tl.Operation.Body = &adapter.Body{Encoding: "xml"}
		tl.Operation.Method = "GET"
	case 3:
		tl.Operation.Kind = "static"
		tl.Operation.Value = nil
	}
}

// TestMalformedAuthPlaceholderDoesNotEchoTheValue guards the one message
// that could carry a literal credential out of a local adapter and into
// a terminal or a CI log: an auth value with a broken placeholder is
// reported by place, never by content.
func TestMalformedAuthPlaceholderDoesNotEchoTheValue(t *testing.T) {
	t.Parallel()
	files, err := adapter.LoadFS(adapters.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no catalog adapters")
	}
	f := *files[0]
	a := *f.Adapter
	a.Auth = adapter.Auth{Type: adapter.AuthBasic, Username: "svc", Password: "hunter2 {{ oops"}
	a.Transport.Headers = adapter.OrderedMap[string]{Keys: []string{"Authorization"}, Values: map[string]string{"Authorization": "Bearer t0ps3cret {{"}}
	f.Adapter = &a
	issues := adapter.Validate(&f)
	syntax := 0
	for _, is := range issues {
		if strings.Contains(is.Message, "hunter2") || strings.Contains(is.Message, "t0ps3cret") {
			t.Errorf("issue echoes a credential: %s", is.Message)
		}
		if is.Rule == "placeholder-syntax" {
			syntax++
		}
	}
	if syntax < 2 {
		t.Errorf("got %d placeholder-syntax issues, want one for the password and one for the header", syntax)
	}
}
