// Package catalog_test renders every tool the catalogue offers that is not
// served by the REST engine. The parity fixture covers REST only, because
// the old engine's dump skipped everything else, so without this the
// graphql and database halves of the catalogue would reach a release
// having never been rendered at all.
package catalog_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/engine/database"
	"github.com/supermcpco/supermcp/internal/engine/graphql"
	"github.com/supermcpco/supermcp/pkg/adapter"
	v1 "github.com/supermcpco/supermcp/pkg/adapter/v1"
	"github.com/supermcpco/supermcp/pkg/adapter/v1compat"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

func TestGraphQLAndDatabaseToolsRender(t *testing.T) {
	adapters := loadCorpus(t)
	counts := map[string]int{}

	for _, a := range adapters {
		if a.Transport.Type == adapter.TransportHTTP {
			continue
		}
		env := map[string]string{}
		for _, name := range a.Credentials.Keys {
			env[name] = "env-" + name
		}
		for i := range a.Tools {
			tool := &a.Tools[i]
			req := &engine.Request{
				Connector: &engine.Connector{
					ID:      a.Metadata.Slug,
					Type:    a.Transport.Type,
					BaseURL: a.Transport.BaseURL,
					Headers: a.Transport.Headers,
					Driver:  a.Transport.Driver,
				},
				Tool: tool,
				Vars: tmpl.Vars{Params: sampleParams(tool, a.Transport.Driver), Env: env},
			}
			name := a.Metadata.Slug + "/" + tool.Name
			switch a.Transport.Type {
			case adapter.TransportGraphQL:
				p, err := (graphql.Engine{}).DryRun(context.Background(), req)
				if err != nil {
					t.Errorf("%s: %v", name, err)
					continue
				}
				var body struct {
					Query string `json:"query"`
				}
				if err := json.Unmarshal([]byte(p.Body), &body); err != nil {
					t.Errorf("%s: the rendered body is not JSON: %v", name, err)
					continue
				}
				if strings.TrimSpace(body.Query) == "" {
					t.Errorf("%s: rendered an empty document", name)
					continue
				}
				if strings.Contains(p.Body, "{{") {
					t.Errorf("%s: a placeholder survived rendering", name)
					continue
				}
				counts["graphql"]++
			case adapter.TransportDatabase:
				p, err := (&database.Engine{}).DryRun(context.Background(), req)
				if err != nil {
					t.Errorf("%s: %v", name, err)
					continue
				}
				if tool.Operation.Kind != "sql" {
					counts["database "+tool.Operation.Kind]++
					continue
				}
				// MongoDB's statement is a JSON document, and the one
				// property that matters is that substitution leaves it
				// parseable.
				if a.Transport.Driver == "mongodb" {
					var doc map[string]any
					if err := json.Unmarshal([]byte(p.SQL), &doc); err != nil {
						t.Errorf("%s: the rendered document is not JSON: %v\n  %s", name, err, p.SQL)
						continue
					}
					if doc["collection"] == nil {
						t.Errorf("%s: the rendered document names no collection\n  %s", name, p.SQL)
						continue
					}
					counts["database mongo"]++
					continue
				}
				// Every catalogue tool reads. A statement that the
				// read-only validator refuses would be refused at call
				// time too, so it must not ship.
				if err := database.ValidateReadOnly(p.SQL); err != nil {
					t.Errorf("%s: %v\n  %s", name, err, p.SQL)
					continue
				}
				counts["database sql"]++
			}
		}
	}

	total := 0
	for _, k := range sortedKeys(counts) {
		total += counts[k]
		t.Logf("  %-18s %d", k, counts[k])
	}
	if total < 60 {
		t.Errorf("only %d tools rendered; the corpus is not what this test expects", total)
	}
}

func loadCorpus(t *testing.T) []*adapter.Adapter {
	t.Helper()
	files, err := v1.LoadDir(filepath.Join("..", "..", "..", "pkg", "adapter", "v1", "testdata", "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	results, err := v1compat.ConvertAll(files)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]*adapter.Adapter, 0, len(results))
	for _, r := range results {
		out = append(out, r.Adapter)
	}
	return out
}

// sampleParams gives every declared parameter a value, by the same rules
// as the REST parity harness.
func sampleParams(tool *adapter.Tool, driver string) map[string]any {
	out := map[string]any{}
	if tool.Input == nil || tool.Input.N == nil {
		return out
	}
	v, err := adapter.NodeValue(tool.Input.N)
	if err != nil {
		return out
	}
	schema, _ := v.(map[string]any)
	props, _ := schema["properties"].(map[string]any)
	for name, raw := range props {
		s, _ := raw.(map[string]any)
		switch {
		case s["default"] != nil:
			out[name] = s["default"]
		case len(asList(s["enum"])) > 0:
			out[name] = asList(s["enum"])[0]
		case name == "query" || name == "sql" || name == "statement":
			// These tools take the statement itself from the caller, so
			// the sample has to be a statement in the dialect the driver
			// speaks. What it may contain is the read-only validator's
			// business at call time.
			if driver == "mongodb" {
				out[name] = `{"collection": "c", "filter": {}}`
			} else {
				out[name] = "SELECT 1"
			}
		default:
			switch s["type"] {
			case "integer":
				out[name] = 7
			case "number":
				out[name] = 2.5
			case "boolean":
				out[name] = true
			case "array":
				out[name] = []any{"a", "b"}
			case "object":
				out[name] = map[string]any{"k": "v"}
			default:
				out[name] = "val-" + name
			}
		}
	}
	return out
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
