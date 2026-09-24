package graphql

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

func TestExecuteVariablesAndErrors(t *testing.T) {
	var gotBody, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotAuth = string(b), r.Header.Get("Authorization")
		if r.Header.Get("X-Fail") == "1" {
			_, _ = w.Write([]byte(`{"data":null,"errors":[{"message":"Field 'x' doesn't exist"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"card":{"slug":"a","n":2}}}`))
	}))
	defer srv.Close()

	vars, _ := adapter.NodeFromJSON([]byte(`{"slug":"{{params.slug}}","first":"{{params.first}}","skip":"{{params.missing}}"}`))
	tool := &adapter.Tool{Name: "t", Operation: adapter.Operation{Kind: "query", Document: "query Q($slug: String!) { card(slug: $slug) { slug } }", Variables: vars}}
	req := &engine.Request{
		Connector: &engine.Connector{BaseURL: srv.URL, Headers: adapter.OrderedMap[string]{Keys: []string{"Authorization"}, Values: map[string]string{"Authorization": "Bearer {{env.T}}"}}},
		Tool:      tool,
		Vars:      tmpl.Vars{Params: map[string]any{"slug": "a", "first": float64(5)}, Env: map[string]string{"T": "tok"}},
		HTTP:      srv.Client(),
	}
	resp, err := (Engine{}).Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if gotBody != `{"query":"query Q($slug: String!) { card(slug: $slug) { slug } }","variables":{"first":5,"slug":"a"}}` {
		t.Errorf("body %s", gotBody)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth %q", gotAuth)
	}
	if m := resp.Body.(map[string]any); m["card"].(map[string]any)["slug"] != "a" {
		t.Errorf("data %#v", resp.Body)
	}

	// GraphQL errors in a 200 become an UpstreamError with the message.
	tool.Operation.Headers = adapter.OrderedMap[string]{Keys: []string{"X-Fail"}, Values: map[string]string{"X-Fail": "1"}}
	_, err = (Engine{}).Execute(context.Background(), req)
	var ue *engine.UpstreamError
	if !errors.As(err, &ue) || ue.Hint == "" {
		t.Fatalf("expected UpstreamError with hint, got %v", err)
	}
}

func TestUnsupportedKind(t *testing.T) {
	req := &engine.Request{Connector: &engine.Connector{BaseURL: "http://x"}, Tool: &adapter.Tool{Operation: adapter.Operation{Kind: "sql"}}, HTTP: http.DefaultClient}
	if _, err := (Engine{}).Execute(context.Background(), req); !errors.Is(err, engine.ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}
