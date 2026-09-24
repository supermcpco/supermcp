package cassette_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/supermcpco/supermcp/internal/cassette"
	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/engine/rest"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

const token = "sk-live-9Z2mQ7pR4tV1wX3y" //nolint:gosec // the point of the test

// TestCredentialCannotSurviveRecording puts one credential everywhere a
// credential can end up — the path, the query, a header, the body, the
// Authorization header, the response body and a Set-Cookie — and proves
// that none of those reaches the file, in any encoding.
func TestCredentialCannotSurviveRecording(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session="+token+"; Path=/")
		w.Header().Set("X-Request-Id", "req-1")
		_, _ = w.Write([]byte(`{"echoed":"` + token + `","ok":true}`))
	}))
	t.Cleanup(upstream.Close)

	body := `{"credential":"` + token + `"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		upstream.URL+"/accounts/"+url.PathEscape(token)+"?key="+url.QueryEscape(token),
		strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Account-Id", token)
	req.Header.Set("Cookie", "session="+token)

	secrets := cassette.NewSecrets(map[string]string{"ACME_API_KEY": token})
	rec := cassette.NewRecorder(upstream.Client(), secrets, cassette.Options{})
	resp, err := rec.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	in, ok := rec.Last()
	if !ok {
		t.Fatal("nothing was recorded")
	}
	c := &cassette.Cassette{Adapter: "acme", Tool: "acme_get_account", Interactions: []cassette.Interaction{in}}
	path := filepath.Join(t.TempDir(), "acme_get_account.yaml")
	if err := c.Save(path, secrets); err != nil {
		t.Fatalf("save: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, form := range []string{
		token,
		url.QueryEscape(token),
		url.PathEscape(token),
		base64.StdEncoding.EncodeToString([]byte(token)),
		base64.RawURLEncoding.EncodeToString([]byte(token)),
	} {
		if bytes.Contains(data, []byte(form)) {
			t.Errorf("the cassette contains the credential as %q:\n%s", form, data)
		}
	}
	marker := cassette.Marker("ACME_API_KEY")
	for _, want := range []string{marker, "echoed"} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("the cassette does not mention %q:\n%s", want, data)
		}
	}
	for _, dropped := range []string{"authorization", "cookie"} {
		if _, found := in.Request.Headers[dropped]; found {
			t.Errorf("the %s header was recorded", dropped)
		}
	}
	if _, found := in.Response.Headers["x-request-id"]; found {
		t.Error("a volatile response header was recorded")
	}
}

// TestSaveRefusesACredentialItCouldNotRedact is the last gate: substitution
// only catches the encodings we thought of, so the bytes are checked too.
func TestSaveRefusesACredentialItCouldNotRedact(t *testing.T) {
	t.Parallel()

	secrets := cassette.NewSecrets(map[string]string{"ACME_API_KEY": token})
	c := &cassette.Cassette{
		Adapter: "acme", Tool: "acme_get_account",
		Interactions: []cassette.Interaction{{
			Request:  cassette.Request{Method: "GET", URL: "https://acme.test/v1/accounts"},
			Response: cassette.Response{Status: 200, Body: `{"rotatedKey":"` + token + `"}`},
		}},
	}
	path := filepath.Join(t.TempDir(), "acme_get_account.yaml")
	err := c.Save(path, secrets)
	if err == nil {
		t.Fatal("a cassette holding a live credential was written")
	}
	if !strings.Contains(err.Error(), "ACME_API_KEY") {
		t.Errorf("the error does not name the credential: %v", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("the file was written anyway")
	}
}

// TestShortValuesAreNotSubstituted guards the other direction: a value of
// three characters is not a secret, and substituting it would rewrite
// innocent text all over a response.
func TestShortValuesAreNotSubstituted(t *testing.T) {
	t.Parallel()

	secrets := cassette.NewSecrets(map[string]string{"ACME_ENV": "eu"})
	if got := secrets.Redact("https://eu.acme.test/queue"); got != "https://eu.acme.test/queue" {
		t.Errorf("redacted a two-character value: %q", got)
	}
}

func TestMatchNamesWhatDiffered(t *testing.T) {
	t.Parallel()

	recorded := cassette.Request{
		Method:  "POST",
		URL:     "https://acme.test/v1/search",
		Query:   "limit=10&page=2",
		Headers: map[string]string{"content-type": "application/json"},
		Body:    `{"a":1,"b":2}`,
	}
	c := &cassette.Cassette{Tool: "acme_search", Interactions: []cassette.Interaction{{
		Request:  recorded,
		Response: cassette.Response{Status: 200, Body: `{"hits":[]}`},
	}}}

	tests := []struct {
		name  string
		build func(cassette.Request) cassette.Request
		want  string // the field the error must name, "" when it must match
	}{
		{"identical", func(r cassette.Request) cassette.Request { return r }, ""},
		{"query reordered", func(r cassette.Request) cassette.Request {
			r.Query = "page=2&limit=10"
			return r
		}, ""},
		{"body keys reordered", func(r cassette.Request) cassette.Request {
			r.Body = `{"b":2,"a":1}`
			return r
		}, ""},
		{"verb changed", func(r cassette.Request) cassette.Request {
			r.Method = "PUT"
			return r
		}, "method"},
		{"path changed", func(r cassette.Request) cassette.Request {
			r.URL = "https://acme.test/v2/search"
			return r
		}, "url"},
		{"query value changed", func(r cassette.Request) cassette.Request {
			r.Query = "limit=10&page=3"
			return r
		}, "query"},
		{"body value changed", func(r cassette.Request) cassette.Request {
			r.Body = `{"a":1,"b":3}`
			return r
		}, "body"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := c.Match(tc.build(recorded))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("expected a match: %v", err)
				}
				return
			}
			var noMatch *cassette.NoMatchError
			if !errors.As(err, &noMatch) {
				t.Fatalf("expected a NoMatchError, got %v", err)
			}
			if len(noMatch.Diffs) != 1 || noMatch.Diffs[0].Field != tc.want {
				t.Fatalf("expected %s to be named, got %v", tc.want, noMatch.Diffs)
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "acme_search") {
				t.Errorf("the message helps nobody: %v", err)
			}
		})
	}
}

func TestEmptyCassetteSaysSo(t *testing.T) {
	t.Parallel()

	c := &cassette.Cassette{Tool: "acme_search"}
	_, err := c.Match(cassette.Request{Method: "GET", URL: "https://acme.test/"})
	if err == nil || !strings.Contains(err.Error(), "no recorded exchanges") {
		t.Fatalf("expected an empty-cassette error, got %v", err)
	}
}

// TestRoundTripThroughTheEngine records a call the way `adapter record`
// does, replays it the way `adapter test` does, and checks the replay
// reaches the same decoded body without a server to talk to.
func TestRoundTripThroughTheEngine(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/items/42" || r.URL.Query().Get("expand") != "true" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":42,"name":"widget"}`))
	}))
	t.Cleanup(upstream.Close)

	tool := parseTool(t, `
name: acme_get_item
description: Get an item.
input:
  type: object
  properties:
    id: {type: integer}
  required: [id]
operation:
  method: GET
  path: /v1/items/{{params.id}}
  query:
    expand: "true"
`)
	conn := &engine.Connector{ID: "acme", Type: adapter.TransportHTTP, BaseURL: upstream.URL}
	vars := tmpl.Vars{Params: map[string]any{"id": 42}}

	rec := cassette.NewRecorder(upstream.Client(), nil, cassette.Options{})
	live, err := (rest.Engine{}).Execute(context.Background(),
		&engine.Request{Connector: conn, Tool: tool, Vars: vars, HTTP: rec})
	if err != nil {
		t.Fatal(err)
	}
	in, ok := rec.Last()
	if !ok {
		t.Fatal("nothing was recorded")
	}
	in.Params = map[string]any{"id": 42}

	path := cassette.Path(t.TempDir(), tool.Name)
	saved := &cassette.Cassette{Adapter: "acme", Tool: tool.Name, Interactions: []cassette.Interaction{in}}
	if err := saved.Save(path, nil); err != nil {
		t.Fatal(err)
	}
	loaded, err := cassette.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	replayed, err := (rest.Engine{}).Execute(context.Background(),
		&engine.Request{Connector: conn, Tool: tool, Vars: vars, HTTP: cassette.NewPlayer(loaded)})
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Status != live.Status {
		t.Errorf("replayed status %d, live %d", replayed.Status, live.Status)
	}
	want, got := renderJSON(t, live.Body), renderJSON(t, replayed.Body)
	if want != got {
		t.Errorf("replayed body %s, live %s", got, want)
	}

	// The upstream is gone: a replay that still answers cannot have dialled.
	upstream.Close()
	if _, err := (rest.Engine{}).Execute(context.Background(),
		&engine.Request{Connector: conn, Tool: tool, Vars: vars, HTTP: cassette.NewPlayer(loaded)}); err != nil {
		t.Fatalf("replay needed the network: %v", err)
	}
}

func TestReplayOfADifferentArgumentFails(t *testing.T) {
	t.Parallel()

	tool := parseTool(t, `
name: acme_get_item
description: Get an item.
input:
  type: object
  properties:
    id: {type: integer}
  required: [id]
operation:
  method: GET
  path: /v1/items/{{params.id}}
`)
	c := &cassette.Cassette{Adapter: "acme", Tool: tool.Name, Interactions: []cassette.Interaction{{
		Params:   map[string]any{"id": 42},
		Request:  cassette.Request{Method: "GET", URL: "https://acme.test/v1/items/42"},
		Response: cassette.Response{Status: 200, Headers: map[string]string{"content-type": "application/json"}, Body: `{"id":42}`},
	}}}
	conn := &engine.Connector{ID: "acme", Type: adapter.TransportHTTP, BaseURL: "https://acme.test"}
	_, err := (rest.Engine{}).Execute(context.Background(), &engine.Request{
		Connector: conn, Tool: tool,
		Vars: tmpl.Vars{Params: map[string]any{"id": 43}},
		HTTP: cassette.NewPlayer(c),
	})
	var noMatch *cassette.NoMatchError
	if !errors.As(err, &noMatch) {
		t.Fatalf("expected a NoMatchError, got %v", err)
	}
	if len(noMatch.Diffs) != 1 || noMatch.Diffs[0].Field != "url" {
		t.Fatalf("expected the url to be named, got %v", noMatch.Diffs)
	}
}

// TestMarkerSurvivesEncoding is why the marker looks the way it does: the
// value replay substitutes must reach the wire unchanged, or every
// credentialed adapter would fail to match itself.
func TestMarkerSurvivesEncoding(t *testing.T) {
	t.Parallel()

	m := cassette.Marker("ACME_API_KEY")
	for _, encoded := range []string{url.QueryEscape(m), url.PathEscape(m)} {
		if encoded != m {
			t.Errorf("the marker changes when encoded: %q", encoded)
		}
	}
}

func parseTool(t *testing.T, src string) *adapter.Tool {
	t.Helper()
	var tool adapter.Tool
	if err := yaml.Unmarshal([]byte(src), &tool); err != nil {
		t.Fatal(err)
	}
	return &tool
}

func renderJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
