package connector

import (
	"errors"
	"strings"
	"testing"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

func parseDef(t *testing.T, js string) *adapter.Tool {
	t.Helper()
	d, err := ParseToolJSON([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestBehaviourChanged(t *testing.T) {
	t.Parallel()
	base := `{"name":"get_x","description":"Reads x.","input":{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}}},
		"operation":{"method":"GET","path":"/x","query":{"a":"{{params.a}}","b":"{{params.b}}"}}}`
	cases := []struct {
		name  string
		after string
		want  bool
	}{
		{"identical", base, false},
		{"description only", strings.Replace(base, "Reads x.", "Reads the x.", 1), false},
		{"input schema only", strings.Replace(base, `"b":{"type":"string"}}}`, `"b":{"type":"integer"}}}`, 1), false},
		{"rename only", strings.Replace(base, `"name":"get_x"`, `"name":"get_y"`, 1), false},
		{"query keys reordered", strings.Replace(base, `"query":{"a":"{{params.a}}","b":"{{params.b}}"}`, `"query":{"b":"{{params.b}}","a":"{{params.a}}"}`, 1), false},
		{"title only", strings.Replace(base, `"operation"`, `"annotations":{"title":"X"},"operation"`, 1), false},
		{"method", strings.Replace(base, `"GET"`, `"DELETE"`, 1), true},
		{"path", strings.Replace(base, `"/x"`, `"/y"`, 1), true},
		{"query value", strings.Replace(base, `"{{params.b}}"`, `"{{env.B}}"`, 1), true},
		{"destructive hint", strings.Replace(base, `"operation"`, `"annotations":{"destructiveHint":false},"operation"`, 1), true},
		{"timeout", strings.Replace(base, `"operation"`, `"timeout":"5s","operation"`, 1), true},
		{"rate limit", strings.Replace(base, `"operation"`, `"rateLimit":{"rps":1},"operation"`, 1), true},
		{"proxy", strings.Replace(base, `"operation"`, `"proxy":false,"operation"`, 1), true},
		{"output", strings.Replace(base, `"operation"`, `"output":{"type":"object"},"operation"`, 1), true},
		{"response transform", strings.TrimSuffix(base, "}") + `,"response":{"transform":{"jmespath":"items"}}}`, true},
	}
	before := parseDef(t, base)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := BehaviourChanged(before, parseDef(t, tc.after)); got != tc.want {
				t.Errorf("BehaviourChanged = %v, want %v", got, tc.want)
			}
		})
	}
	if !BehaviourChanged(nil, before) || BehaviourChanged(nil, nil) {
		t.Error("nil handling")
	}
}

func TestPathHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		host string
		ok   bool
	}{
		{"", "", false},
		{"/v1/items", "", false},
		{"items/{{params.id}}", "", false},
		{"{{params.id}}/items", "", false},
		{"https://api.example.com/v1", "api.example.com", true},
		{"HTTPS://API.Example.com", "api.example.com", true},
		{"http://api.example.com:8080?x=1", "api.example.com:8080", true},
		{"https://user:pw@evil.example/x", "evil.example", true},
		{"https://{{params.region}}.example.com/x", "{{params.region}}.example.com", true},
		{"{{params.url | raw}}", "{{params.url | raw}}", true},
		{"{{params.url|raw}}/x", "{{params.url|raw}}", true},
		{"  https://api.example.com  ", "api.example.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			host, ok := pathHost(tc.path)
			if host != tc.host || ok != tc.ok {
				t.Errorf("pathHost(%q) = %q, %v; want %q, %v", tc.path, host, ok, tc.host, tc.ok)
			}
		})
	}
}

// TestDefinitionRoundTrip checks the wire form of a definition: ordered
// maps (headers) keep their order, free-form nodes (input, query) come out
// with sorted keys, and encoding what was decoded gives the same bytes, so
// a restore reproduces the definition exactly.
func TestDefinitionRoundTrip(t *testing.T) {
	t.Parallel()
	in := `{"name":"get_x","description":"Reads x.","input":{"type":"object","properties":{"zeta":{"type":"string"},"alpha":{"type":"string"}},"required":["zeta"]},` +
		`"operation":{"method":"GET","path":"/x","query":{"zeta":"{{params.zeta}}","alpha":"{{params.alpha}}"},"headers":{"X-B":"1","X-A":"2"}}}`
	out, err := DefinitionJSON(parseDef(t, in))
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{`"X-B"`, `"X-A"`}, {`"alpha":{"type"`, `"zeta":{"type"`}, {`"alpha":"{{`, `"zeta":"{{`}} {
		i, j := strings.Index(string(out), pair[0]), strings.Index(string(out), pair[1])
		if i < 0 || j < 0 || i > j {
			t.Errorf("want %s before %s in %s", pair[0], pair[1], out)
		}
	}
	again, err := DefinitionJSON(parseDef(t, string(out)))
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(out) {
		t.Errorf("second round trip differs:\n%s\n%s", out, again)
	}
}

func TestInvalidToolErrorListsErrorsOnly(t *testing.T) {
	t.Parallel()
	err := error(&InvalidToolError{Issues: []adapter.Issue{
		{Severity: adapter.SeverityWarning, Message: "a warning"},
		{Severity: adapter.SeverityError, Field: "operation.path", Message: "bad host"},
	}})
	var inv *InvalidToolError
	if !errors.As(err, &inv) || strings.Contains(err.Error(), "a warning") || !strings.Contains(err.Error(), "operation.path: bad host") {
		t.Errorf("Error() = %q", err.Error())
	}
}

func TestWarningsOf(t *testing.T) {
	t.Parallel()
	in := []adapter.Issue{{Rule: "a", Severity: adapter.SeverityError}, {Rule: "b", Severity: adapter.SeverityWarning}}
	if hasErrors(warningsOf(in)) || !hasErrors(in) || len(warningsOf(in)) != 1 {
		t.Errorf("warningsOf/hasErrors wrong")
	}
}
