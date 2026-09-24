package rest_test

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/engine/rest"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

// The parity fixture only holds the requests the old engine managed to
// build. It refused 554 of them at build time, because its SSRF guard
// resolved the host before the request existed and an adapter whose base
// URL is a customer's own address ("env-WOOCOMMERCE_URL") has no host to
// resolve. Those tools are the self-hosted half of the catalogue, and a
// parity run that quietly skipped them would report a number that means
// less than it looks.
//
// This test closes that gap from the other side: every tool in the
// catalogue is named, and each one is either compared against the old
// engine by TestParityWithLegacyEngine or built here with the same
// synthetic input, so that no tool reaches a release without something
// having rendered it at least once.

func TestEveryToolAccountedFor(t *testing.T) {
	refs := loadReferences(t)
	corpus := loadCorpus(t)

	compared := map[string]bool{}
	refused := map[string]string{}
	for _, r := range refs {
		key := r.Adapter + "/" + r.Tool
		if r.Error != "" {
			refused[key] = r.Error
			continue
		}
		if r.URL != "" {
			compared[key] = true
		}
	}

	cap := &capture{}
	client := &http.Client{Transport: cap}
	counts := map[string]int{}
	var failures []string

	slugs := make([]string, 0, len(corpus))
	for slug := range corpus {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)

	for _, slug := range slugs {
		c := corpus[slug]
		env := map[string]string{}
		for _, name := range c.adapter.Credentials.Keys {
			env[name] = envSample(name)
		}
		names := make([]string, 0, len(c.tools))
		for name := range c.tools {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			tool := c.tools[name]
			key := slug + "/" + name
			if c.adapter.Transport.Type != adapter.TransportHTTP {
				// GraphQL and database adapters have their own engines and
				// their own tests; the old engine's dump never covered them.
				counts["transport "+string(c.adapter.Transport.Type)]++
				continue
			}
			if tool.Operation.Method == "" {
				counts["no request to build (static)"]++
				continue
			}
			req := &engine.Request{
				Connector: &engine.Connector{
					ID:      slug,
					Type:    adapter.TransportHTTP,
					BaseURL: c.adapter.Transport.BaseURL,
					Headers: c.adapter.Transport.Headers,
				},
				Tool: tool,
				Vars: tmpl.Vars{Params: synthParams(tool), Env: env},
				HTTP: client,
			}
			_, err := (rest.Engine{}).Execute(context.Background(), req)
			switch {
			case err != nil:
				counts["will not build"]++
				if len(failures) < 10 {
					failures = append(failures, fmt.Sprintf("%s: %v", key, err))
				}
			case compared[key]:
				counts["compared against the old engine"]++
			case refused[key] != "":
				counts["the old engine refused it; we build it"]++
			default:
				counts["no reference; we build it"]++
			}
		}
	}

	total := 0
	for _, k := range sortedKeys(counts) {
		total += counts[k]
		t.Logf("  %-34s %d", k, counts[k])
	}
	t.Logf("%d tools accounted for across %d adapters", total, len(corpus))
	for _, f := range failures {
		t.Errorf("no request could be built: %s", f)
	}
	if n := counts["compared against the old engine"]; n < 1500 {
		t.Errorf("only %d tools were compared against the old engine", n)
	}
	if total < 2300 {
		t.Errorf("only %d tools were accounted for; the corpus is not what this test expects", total)
	}
}

// envSample matches the dump script, except that a credential holding a
// port gets a port: "env-SAP_B1_PORT" in the authority is not a URL, and
// failing on it would be the test reporting its own input.
func envSample(name string) string {
	if strings.HasSuffix(name, "_PORT") {
		return "443"
	}
	return "env-" + name
}

// synthParams gives every declared parameter a value, by the same rules as
// scripts/dump-v1-requests.cts, so the two engines are fed the same input.
func synthParams(tool *adapter.Tool) map[string]any {
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
		out[name] = sampleFor(raw, name)
	}
	return out
}

func sampleFor(raw any, name string) any {
	s, _ := raw.(map[string]any)
	if d, ok := s["default"]; ok {
		return d
	}
	if enum, ok := s["enum"].([]any); ok && len(enum) > 0 {
		return enum[0]
	}
	switch s["type"] {
	case "integer":
		return 7
	case "number":
		return 2.5
	case "boolean":
		return true
	case "array":
		return []any{"a", "b"}
	case "object":
		return map[string]any{"k": "v"}
	default:
		return "val-" + name
	}
}
