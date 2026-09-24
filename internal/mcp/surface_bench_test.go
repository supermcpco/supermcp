package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/mcpserver"
	"github.com/supermcpco/supermcp/internal/tool"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// The plan's gate: a caller with 500 tools must get its surface rebuilt in
// under 5 ms, because the rebuild happens on every single MCP request and
// the budget for the whole call is 300 ms of gateway overhead.
const (
	gateTools       = 500
	gateBudget      = 5 // milliseconds
	benchConnectors = 10
	toolsPerCon     = gateTools / benchConnectors
)

// benchSchema is the shape of an ordinary REST tool: a handful of typed
// parameters with descriptions. A one-property schema would make the
// serialisation look free, which is the part a large catalogue pays for.
const benchSchema = `{
  "type": "object",
  "properties": {
    "id": {"type": "string", "description": "Identifier of the record to fetch."},
    "page": {"type": "integer", "description": "Page number, starting at 1.", "default": 1},
    "perPage": {"type": "integer", "description": "How many records to return.", "default": 25},
    "expand": {"type": "array", "items": {"type": "string"}, "description": "Related records to inline."},
    "filter": {"type": "object", "description": "Field equality filters.", "additionalProperties": {"type": "string"}}
  },
  "required": ["id"]
}`

// fabricate builds a surface of n tools without touching a database. It is
// the shape buildSurface would have produced: tools spread across several
// connectors, annotations already derived, names deduplicated.
func fabricate(tb testing.TB, n int) *surface {
	tb.Helper()
	input, err := adapter.NodeFromJSON([]byte(benchSchema))
	if err != nil {
		tb.Fatal(err)
	}
	srv := &mcpserver.Server{ID: "srv_bench", OrgID: "org_bench", Slug: "bench", Name: "Bench", Enabled: true}
	out := &surface{server: srv, instructionsText: "Use the bench API.", names: make(map[string]bool, n), tools: make([]visibleTool, 0, n)}
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	for i := range n {
		c := benchConnector(i / toolsPerCon)
		t := &connector.Tool{
			ID:          fmt.Sprintf("tl_%04d", i),
			ConnectorID: c.ID,
			Name:        fmt.Sprintf("%s_operation_%04d", strings.ReplaceAll(c.Name, "-", "_"), i),
			Enabled:     true,
			Definition: &adapter.Tool{
				Name:        fmt.Sprintf("%s_operation_%04d", strings.ReplaceAll(c.Name, "-", "_"), i),
				Description: "Fetch, create or amend one record in the bench API. This description is about as long as a real catalogue entry, which matters because every byte of it is serialised on every tools/list.",
				Input:       input,
				Operation:   adapter.Operation{Method: methods[i%len(methods)], Path: fmt.Sprintf("/records/%d", i)},
			},
		}
		ann := tool.Derive(t.Definition, c.Transport.Type, c.ReadOnly)
		out.names[t.Name] = true
		out.tools = append(out.tools, visibleTool{tool: t, connector: c, ann: ann})
	}
	return out
}

func benchConnector(i int) *connector.Connector {
	return &connector.Connector{
		ID:        fmt.Sprintf("cn_%02d", i),
		OrgID:     "org_bench",
		Name:      fmt.Sprintf("bench-%02d", i),
		Transport: adapter.Transport{Type: adapter.TransportHTTP, BaseURL: "https://bench.invalid"},
		Enabled:   true,
	}
}

// surfaceTools is what mcpserver.Surface hands buildSurface, rebuilt here
// so the annotation pass can be measured without a database.
func surfaceTools(s *surface) []mcpserver.SurfaceTool {
	out := make([]mcpserver.SurfaceTool, 0, len(s.tools))
	for _, vt := range s.tools {
		out = append(out, mcpserver.SurfaceTool{Tool: vt.tool, Connector: vt.connector})
	}
	return out
}

// BenchmarkSurfaceAnnotate measures the per-request work in buildSurface
// once the rows are in hand: derive annotations, deduplicate names, collect
// the visible set. The database reads and the authorisation calls around it
// are excluded on purpose — they are measured against a real Postgres, and
// mixing them in here would hide a regression in this loop.
func BenchmarkSurfaceAnnotate(b *testing.B) {
	src := surfaceTools(fabricate(b, gateTools))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		out := &surface{names: make(map[string]bool, len(src)), tools: make([]visibleTool, 0, len(src))}
		for _, st := range src {
			ann := tool.Derive(st.Tool.Definition, st.Connector.Transport.Type, st.Connector.ReadOnly)
			if out.names[st.Tool.Name] {
				continue
			}
			out.names[st.Tool.Name] = true
			out.tools = append(out.tools, visibleTool{tool: st.Tool, connector: st.Connector, ann: ann})
		}
		if len(out.tools) != gateTools {
			b.Fatalf("fabricated %d tools, surface has %d", gateTools, len(out.tools))
		}
	}
}

// BenchmarkAssemble measures the second half of a rebuild: converting
// every visible tool into the wire shape and registering it on a fresh SDK
// server. This is what the surface cache exists to avoid paying twice —
// almost all of it is the SDK re-parsing each input schema.
func BenchmarkAssemble(b *testing.B) {
	e := New(Deps{Version: "bench"})
	s := fabricate(b, gateTools)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if srv := e.assemble(s); srv == nil {
			b.Fatal("no server built")
		}
	}
}

// BenchmarkToolsList is the gate: one whole tools/list request at 500
// tools, surface rebuild included, answered through the real handler. The
// allocation figure matters as much as the time — a rebuild that allocates
// a megabyte per request is a garbage-collector problem at 500 rps even
// when each one looks fast on its own.
func BenchmarkToolsList(b *testing.B) {
	for _, n := range []int{10, 100, gateTools} {
		b.Run(fmt.Sprintf("tools=%d", n), func(b *testing.B) {
			e := New(Deps{Version: "bench"})
			s := fabricate(b, n)
			s.mcp = e.assemble(s) // as buildSurface leaves it, or finds it cached
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				rec := httptest.NewRecorder()
				e.handler.ServeHTTP(rec, surfaceRequest(b, body, s))
				if rec.Code != http.StatusOK {
					b.Fatalf("status %d: %s", rec.Code, rec.Body.String())
				}
			}
		})
	}
}

// allocCeiling is a ratchet, not an aspiration. Answering tools/list for
// 500 tools from an assembled surface costs about 60 allocations per tool,
// nearly all of them the response itself; assembling that surface costs
// about 260 per tool, which is why it is assembled once per server,
// version and caller rather than once per request.
//
// The ceiling is set above the measured figure so a change that adds
// another round trip through JSON fails here, on any machine, rather than
// showing up as a latency graph nobody was watching. A wall-clock
// assertion is deliberately not made in CI, because a shared runner would
// make it flap; run `go test -bench BenchmarkToolsList ./internal/mcp/` on
// the hardware you intend to deploy on and read the number there.
const allocCeiling = 100

// TestSurfaceRebuildAllocations guards the per-request rebuild against
// growing another allocation pass. Allocations are asserted rather than
// time because they are the same on a laptop and on a runner, and because
// at 500 rps the garbage they make is what costs the tail latency.
func TestSurfaceRebuildAllocations(t *testing.T) {
	if testing.Short() {
		t.Skip("the ceiling is a measurement; it needs the full run")
	}
	e := New(Deps{Version: "gate"})
	s := fabricate(t, gateTools)
	s.mcp = e.assemble(s)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			rec := httptest.NewRecorder()
			e.handler.ServeHTTP(rec, surfaceRequest(b, body, s))
			if rec.Code != http.StatusOK {
				b.Fatalf("status %d", rec.Code)
			}
		}
	})
	if res.N == 0 {
		t.Fatal("the benchmark did not run")
	}
	perOp := res.T / time.Duration(res.N)
	perTool := res.AllocsPerOp() / gateTools
	t.Logf("tools/list at %d tools: %v, %d B/op, %d allocs/op (%d per tool); the plan's gate is %d ms",
		gateTools, perOp, res.AllocedBytesPerOp(), res.AllocsPerOp(), perTool, gateBudget)
	if perTool > allocCeiling {
		t.Errorf("rebuilding one tool allocates %d times, over the ceiling of %d", perTool, allocCeiling)
	}
}

// surfaceRequest builds the request the endpoint would have handed the SDK
// handler: the JSON-RPC body, the Accept header the Streamable HTTP
// transport requires, and the surface already in the context.
func surfaceRequest(tb testing.TB, body string, s *surface) *http.Request {
	tb.Helper()
	r := httptest.NewRequest(http.MethodPost, "/mcp/bench", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	return r.WithContext(context.WithValue(r.Context(), surfaceKey, s))
}
