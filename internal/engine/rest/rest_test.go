package rest

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

type captured struct {
	method, path, query, body, contentType, auth string
}

func upstream(t *testing.T, respond func(w http.ResponseWriter, c captured)) (*httptest.Server, *captured) {
	t.Helper()
	var last captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		last = captured{method: r.Method, path: r.URL.EscapedPath(), query: r.URL.RawQuery, body: string(b), contentType: r.Header.Get("Content-Type"), auth: r.Header.Get("Authorization")}
		respond(w, last)
	}))
	t.Cleanup(srv.Close)
	return srv, &last
}

func node(t *testing.T, yamlOrJSON string) *adapter.Node {
	t.Helper()
	n, err := adapter.NodeFromJSON([]byte(yamlOrJSON))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func request(srv *httptest.Server, tool *adapter.Tool, params map[string]any) *engine.Request {
	return &engine.Request{
		Connector: &engine.Connector{ID: "c1", Type: adapter.TransportHTTP, BaseURL: srv.URL + "/v1/"},
		Tool:      tool,
		Vars:      tmpl.Vars{Params: params, Env: map[string]string{"KEY": "k"}},
		HTTP:      srv.Client(),
	}
}

func TestQueryEncodingMatchesLegacy(t *testing.T) {
	srv, got := upstream(t, func(w http.ResponseWriter, _ captured) { w.Write([]byte(`{"ok":true}`)) })
	tool := &adapter.Tool{Name: "t", Operation: adapter.Operation{
		Method: "GET", Path: "/items/{{params.id}}",
		Query: node(t, `{"filter":"{{params.filter}}","columns":"{{params.cols}}","n":"{{params.n}}","skip":"{{params.missing}}","lit":"a b"}`),
	}}
	resp, err := (Engine{}).Execute(context.Background(), request(srv, tool, map[string]any{
		"id": "a/b", "filter": "date ge 2026-09-01T00:00:00Z,x$y", "cols": []any{"c1", "c2"}, "n": float64(3),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got.path != "/v1/items/a%2Fb" {
		t.Errorf("path %q", got.path)
	}
	want := "filter=date+ge+2026-09-01T00:00:00Z,x$y&columns=c1&columns=c2&n=3&lit=a+b"
	if got.query != want {
		t.Errorf("query\n got %q\nwant %q", got.query, want)
	}
	if m, ok := resp.Body.(map[string]any); !ok || m["ok"] != true {
		t.Errorf("body %#v", resp.Body)
	}
}

func TestRawQueryHatch(t *testing.T) {
	srv, got := upstream(t, func(w http.ResponseWriter, _ captured) { w.Write([]byte(`[]`)) })
	tool := &adapter.Tool{Name: "t", Operation: adapter.Operation{Method: "GET", Path: "/x", Query: node(t, `{"__rawquery":"{{params.q}}","page":"1"}`)}}
	if _, err := (Engine{}).Execute(context.Background(), request(srv, tool, map[string]any{"q": "articleNumber-eq=A5101&active-eq=true"})); err != nil {
		t.Fatal(err)
	}
	if got.query != "page=1&active-eq=true&articleNumber-eq=A5101" {
		t.Errorf("query %q", got.query)
	}
}

func TestJSONBodyTypedAndDropsUnset(t *testing.T) {
	srv, got := upstream(t, func(w http.ResponseWriter, _ captured) { w.WriteHeader(201); w.Write([]byte(`{"id":1}`)) })
	tool := &adapter.Tool{Name: "t", Operation: adapter.Operation{Method: "POST", Path: "/x",
		Body: &adapter.Body{Value: node(t, `{"name":"{{params.name}}","qty":"{{params.qty}}","tags":"{{params.tags}}","opt":"{{params.missing}}","nested":{"k":"{{params.name}}-x"}}`)}}}
	resp, err := (Engine{}).Execute(context.Background(), request(srv, tool, map[string]any{"name": "a&b<c>", "qty": float64(2), "tags": []any{"x"}}))
	if err != nil {
		t.Fatal(err)
	}
	if got.contentType != "application/json" {
		t.Errorf("content-type %q", got.contentType)
	}
	if got.body != `{"name":"a&b<c>","nested":{"k":"a&b<c>-x"},"qty":2,"tags":["x"]}` {
		t.Errorf("body %s", got.body)
	}
	if resp.Status != 201 {
		t.Errorf("status %d", resp.Status)
	}
}

func TestFormBodyBracketsAndSpread(t *testing.T) {
	srv, got := upstream(t, func(w http.ResponseWriter, _ captured) { w.Write([]byte(`ok`)) })
	tool := &adapter.Tool{Name: "t", Operation: adapter.Operation{Method: "POST", Path: "/x",
		Body: &adapter.Body{Encoding: "form", Value: node(t, `{"fields":"{{params.fields}}","__spread":"{{params.extra}}"}`)}}}
	_, err := (Engine{}).Execute(context.Background(), request(srv, tool, map[string]any{
		"fields": map[string]any{"TITLE": "x y", "TAGS": []any{"a", "b"}},
		"extra":  map[string]any{"taskId": float64(1)},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got.contentType != "application/x-www-form-urlencoded" {
		t.Errorf("content-type %q", got.contentType)
	}
	if got.body != "fields%5BTAGS%5D%5B0%5D=a&fields%5BTAGS%5D%5B1%5D=b&fields%5BTITLE%5D=x+y&taskId=1" {
		t.Errorf("body %s", got.body)
	}
}

func TestRawBodyAndHeaderPrecedence(t *testing.T) {
	srv, got := upstream(t, func(w http.ResponseWriter, _ captured) {
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(`<r><a b="1">x</a><n>2</n></r>`))
	})
	tool := &adapter.Tool{Name: "t", Operation: adapter.Operation{Method: "POST", Path: "/x",
		Headers: adapter.OrderedMap[string]{Keys: []string{"Content-Type", "X-Key"}, Values: map[string]string{"Content-Type": "text/xml", "X-Key": "{{env.KEY}}"}},
		Body:    &adapter.Body{Encoding: "raw", Value: node(t, `"<q>{{params.v}}</q>"`)}}}
	req := request(srv, tool, map[string]any{"v": "1"})
	req.Connector.Headers = adapter.OrderedMap[string]{Keys: []string{"Content-Type", "Accept"}, Values: map[string]string{"Content-Type": "application/json", "Accept": "*/*"}}
	resp, err := (Engine{}).Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if got.body != "<q>1</q>" || got.contentType != "text/xml" {
		t.Errorf("body %q ct %q", got.body, got.contentType)
	}
	m, ok := resp.Body.(map[string]any)
	if !ok {
		t.Fatalf("xml not parsed: %#v", resp.Body)
	}
	r := m["r"].(map[string]any)
	if r["n"] != "2" || r["a"].(map[string]any)["-b"] != "1" {
		t.Errorf("xml map %#v", m)
	}
}

func TestUpstreamErrorAndExposeHeaders(t *testing.T) {
	srv, _ := upstream(t, func(w http.ResponseWriter, _ captured) {
		w.Header().Set("Link", `<https://x/next>; rel="next"`)
		w.WriteHeader(404)
		w.Write([]byte(`{"error":"nope"}`))
	})
	tool := &adapter.Tool{Name: "t", Operation: adapter.Operation{Method: "GET", Path: "/x"}, Response: &adapter.Response{ExposeHeaders: []string{"Link"}}}
	resp, err := (Engine{}).Execute(context.Background(), request(srv, tool, nil))
	var ue *engine.UpstreamError
	if err == nil || !asUpstream(err, &ue) || ue.Status != 404 {
		t.Fatalf("expected UpstreamError 404, got %v", err)
	}
	if resp == nil || resp.Headers["link"] == "" {
		t.Errorf("expose headers missing: %#v", resp)
	}
}

func asUpstream(err error, target **engine.UpstreamError) bool {
	return errors.As(err, target)
}

type refresher struct {
	token   string
	refresh int
}

func (r *refresher) Apply(_ context.Context, req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+r.token)
	return nil
}
func (r *refresher) Refresh(context.Context) (bool, error) {
	r.refresh++
	r.token = "new"
	return true, nil
}

func TestRefreshOn401Once(t *testing.T) {
	srv, got := upstream(t, func(w http.ResponseWriter, c captured) {
		if c.auth != "Bearer new" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"ok":1}`))
	})
	tool := &adapter.Tool{Name: "t", Operation: adapter.Operation{Method: "GET", Path: "/x"}}
	req := request(srv, tool, nil)
	r := &refresher{token: "old"}
	req.Auth = r
	resp, err := (Engine{}).Execute(context.Background(), req)
	if err != nil || resp.Status != 200 || r.refresh != 1 || got.auth != "Bearer new" || !resp.Meta.AuthRefreshed {
		t.Fatalf("resp=%+v err=%v refresh=%d auth=%q", resp, err, r.refresh, got.auth)
	}
}

func TestBinaryStreamAndDryRun(t *testing.T) {
	srv, _ := upstream(t, func(w http.ResponseWriter, _ captured) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("\x89PNG"))
	})
	tool := &adapter.Tool{Name: "t", Operation: adapter.Operation{Method: "GET", Path: "/img", Headers: adapter.OrderedMap[string]{Keys: []string{"X-Api-Key"}, Values: map[string]string{"X-Api-Key": "{{env.KEY}}"}}}}
	req := request(srv, tool, nil)
	resp, err := (Engine{}).Execute(context.Background(), req)
	if err != nil || resp.Stream == nil || resp.MediaType != "image/png" {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
	data, _ := io.ReadAll(resp.Stream)
	resp.Stream.Close()
	if string(data) != "\x89PNG" {
		t.Errorf("stream %q", data)
	}
	p, err := (Engine{}).DryRun(context.Background(), req)
	if err != nil || p.Method != "GET" || !strings.HasSuffix(p.URL, "/v1/img") || p.Headers["X-Api-Key"] != "<redacted>" {
		t.Errorf("preview %+v err=%v", p, err)
	}
}
