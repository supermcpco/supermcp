package tmpl

import (
	"errors"
	"reflect"
	"testing"
)

var vars = Vars{
	Params: map[string]any{
		"id": "42", "n": float64(7), "on": true, "tags": []any{"a", "b"}, "obj": map[string]any{"k": "v"},
		"path": "a/b c", "nested": map[string]any{"deep": "x"}, "empty": "",
	},
	Env:    map[string]string{"API_KEY": "sekret", "ORG": "acme"},
	Caller: map[string]string{"email": "u@example.com"},
	Auth:   map[string]string{"token": "tok"},
	Req:    map[string]string{"method": "GET"},
}

func TestRenderWholeValueTyped(t *testing.T) {
	cases := []struct {
		in   string
		want any
		ok   bool
	}{
		{"{{params.id}}", "42", true},
		{"{{params.n}}", float64(7), true},
		{"{{params.on}}", true, true},
		{"{{params.tags}}", []any{"a", "b"}, true},
		{"{{params.obj}}", map[string]any{"k": "v"}, true},
		{"{{params.nested.deep}}", "x", true},
		{"{{params.tags.1}}", "b", true},
		{"{{params.missing}}", nil, false},
		{"{{params.empty}}", "", true},
		{"{{params.missing | default:5}}", float64(5), true},
		{`{{params.missing | default:"x"}}`, "x", true},
		{"{{params.tags | join:;}}", "a;b", true},
		{"{{params.obj | json}}", `{"k":"v"}`, true},
		{"{{env.API_KEY}}", "sekret", true},
		{"{{caller.email}}", "u@example.com", true},
		{"{{auth.token}}", "tok", true},
		{"{{req.method}}", "GET", true},
		{`{{ "{{" }}`, "{{", true},
		{"plain", "plain", true},
	}
	for _, c := range cases {
		got, ok, err := Render(c.in, vars, Value)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if ok != c.ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got (%#v, %v), want (%#v, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestRenderInterpolation(t *testing.T) {
	got, ok, err := Render("Bearer {{auth.token}} for {{params.id}}/{{params.n}}", vars, Value)
	if err != nil || !ok || got != "Bearer tok for 42/7" {
		t.Fatalf("got %#v %v %v", got, ok, err)
	}
	// Missing reference in Value mode: whole string unset.
	_, ok, err = Render("x={{params.missing}}", vars, Value)
	if err != nil || ok {
		t.Fatalf("expected unset, got ok=%v err=%v", ok, err)
	}
	// Missing in Strict mode: error naming the placeholder.
	_, _, err = Render("x={{params.missing}}", vars, Strict)
	if !errors.Is(err, ErrUnset) {
		t.Fatalf("expected ErrUnset, got %v", err)
	}
}

func TestRenderPathEscaping(t *testing.T) {
	got, err := RenderString("/users/{{params.path}}/x", vars, Path)
	if err != nil || got != "/users/a%2Fb%20c/x" {
		t.Fatalf("got %q %v", got, err)
	}
	got, err = RenderString("/users/{{params.path | raw}}/x", vars, Path)
	if err != nil || got != "/users/a/b c/x" {
		t.Fatalf("raw: got %q %v", got, err)
	}
	if _, err := RenderString("/{{params.missing}}", vars, Path); !errors.Is(err, ErrUnset) {
		t.Fatalf("expected ErrUnset, got %v", err)
	}
	// Env in path is not user input but is still escaped unless raw.
	got, _ = RenderString("/{{env.ORG}}/v1", vars, Path)
	if got != "/acme/v1" {
		t.Fatalf("got %q", got)
	}
}

func TestRenderValueDropsUnset(t *testing.T) {
	in := map[string]any{
		"keep":   "{{params.id}}",
		"drop":   "{{params.missing}}",
		"drop2":  "pre-{{params.missing}}",
		"typed":  "{{params.n}}",
		"nested": map[string]any{"a": "{{params.on}}", "b": "{{params.missing}}"},
		"list":   []any{"{{params.id}}", "{{params.missing}}", "lit"},
		"lit":    float64(1),
	}
	out, err := RenderValue(in, vars)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"keep":   "42",
		"typed":  float64(7),
		"nested": map[string]any{"a": true},
		"list":   []any{"42", "lit"},
		"lit":    float64(1),
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("got %#v\nwant %#v", out, want)
	}
}

func TestSQL(t *testing.T) {
	stmt := "SELECT * FROM t WHERE id = {{params.id}} AND n > {{params.n}} AND org = '{{env.ORG}}' AND x = {{params.missing}}"
	cases := map[Dialect]string{
		Postgres: "SELECT * FROM t WHERE id = $1 AND n > $2 AND org = 'acme' AND x = $3",
		MySQL:    "SELECT * FROM t WHERE id = ? AND n > ? AND org = 'acme' AND x = ?",
		MSSQL:    "SELECT * FROM t WHERE id = @p0 AND n > @p1 AND org = 'acme' AND x = @p2",
		Oracle:   "SELECT * FROM t WHERE id = :b0 AND n > :b1 AND org = 'acme' AND x = :b2",
	}
	for d, want := range cases {
		got, args, err := SQL(stmt, vars, d)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("dialect %d: got %q want %q", d, got, want)
		}
		if !reflect.DeepEqual(args, []any{"42", float64(7), nil}) {
			t.Errorf("dialect %d: args %#v", d, args)
		}
	}
	// Raw splices operator-provided text.
	raw := Vars{Params: map[string]any{"query": "SELECT 1"}}
	got, args, err := SQL("{{params.query | raw}}", raw, Postgres)
	if err != nil || got != "SELECT 1" || len(args) != 0 {
		t.Fatalf("raw: %q %v %v", got, args, err)
	}
}

func TestRefsErrors(t *testing.T) {
	for _, bad := range []string{"{{params}}", "{{nope.x}}", "{{params.x", "{{params.x | bogus}}", "{{params.x | raw:1}}"} {
		if _, err := Refs(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
	if got := Names("{{params.a}} {{env.B}} {{params.a}}"); !reflect.DeepEqual(got, []string{"env.B", "params.a"}) {
		t.Errorf("Names: %v", got)
	}
}

func TestStringify(t *testing.T) {
	cases := map[any]string{float64(3): "3", 2.5: "2.5", true: "true", "s": "s", nil: ""}
	for in, want := range cases {
		if got := Stringify(in); got != want {
			t.Errorf("%v: got %q want %q", in, got, want)
		}
	}
}
