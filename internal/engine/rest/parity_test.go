package rest_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/engine/rest"
	"github.com/supermcpco/supermcp/pkg/adapter"
	v1 "github.com/supermcpco/supermcp/pkg/adapter/v1"
	"github.com/supermcpco/supermcp/pkg/adapter/v1compat"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

// reference is one request as the legacy v1 engine built it, recorded by
// scripts/dump-v1-requests.cts run against that engine. Each tool
// was called with a synthetic value per declared parameter, so the pair of
// engines is fed identical input.
type reference struct {
	Adapter string            `json:"adapter"`
	Tool    string            `json:"tool"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Query   string            `json:"query"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Params  map[string]any    `json:"params"`
	Env     map[string]string `json:"env"`
	Error   string            `json:"error"`
}

// capture answers every request without a network call and keeps what was
// about to go on the wire.
type capture struct {
	req  *http.Request
	body []byte
}

func (c *capture) RoundTrip(r *http.Request) (*http.Response, error) {
	c.req = r
	c.body = nil
	if r.Body != nil {
		c.body, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
		Request:    r,
	}, nil
}

// headersNotCompared are set by a transport rather than by the adapter, or
// are axios defaults that never reached the wire.
var headersNotCompared = map[string]bool{
	"content-length": true, "user-agent": true, "accept": true,
	"accept-encoding": true, "host": true, "connection": true,
}

// divergence is a difference from the old engine that this port makes on
// purpose. Each entry names the adapter and what the old engine did.
type divergence struct {
	kinds  []string
	reason string
}

var divergences = map[string]divergence{
	// resolveValue only substituted a header value that was exactly "$name",
	// so "Bearer ${access_jwt}" went upstream with the braces intact and
	// every call 401'd. The parameter is declared and supplied; we resolve it.
	"bluesky": {kinds: []string{"header authorization"},
		reason: "v1 sent the literal ${access_jwt} in the Authorization header"},
	// The header names an environment variable the adapter never declares,
	// so there is nothing to resolve. v1 sent the braces; we drop the header
	// and `adapter validate` reports the undeclared credential.
	"statsig": {kinds: []string{"header statsig-api-key"},
		reason: "v1 sent the literal {{STATSIG_CONSOLE_API_KEY}}, which the adapter never declares"},
	// v1 attached a body only to POST/PUT/PATCH, so a DELETE that needs one
	// was sent empty and rejected upstream.
	"coda":     {kinds: []string{"body"}, reason: "v1 dropped the body of a DELETE"},
	"fillout":  {kinds: []string{"body"}, reason: "v1 dropped the body of a DELETE"},
	"klaviyo":  {kinds: []string{"body"}, reason: "v1 dropped the body of a DELETE"},
	"savvycal": {kinds: []string{"body"}, reason: "v1 dropped the body of a DELETE"},
	// An object-valued query parameter reached JavaScript's default string
	// conversion and went upstream as the literal "[object Object]".
	"salesloft": {kinds: []string{"query"}, reason: "v1 sent [object Object] for an object-valued query parameter"},
}

// TestParityWithLegacyEngine replays every recorded request through this
// engine and compares what goes on the wire. The converter and the engine
// together have to reproduce the system being replaced; schema validity
// would not show that.
func TestParityWithLegacyEngine(t *testing.T) {
	refs := loadReferences(t)
	tools := loadCorpus(t)

	examples := 3 // PARITY_EXAMPLES raises the cap while chasing a difference
	if n, err := strconv.Atoi(os.Getenv("PARITY_EXAMPLES")); err == nil && n > 0 {
		examples = n
	}

	cap := &capture{}
	client := &http.Client{Transport: cap}

	var compared, skipped, expected int
	mismatches := map[string]int{}
	for _, ref := range refs {
		if ref.Error != "" || ref.URL == "" {
			skipped++ // the old engine refused to build this one
			continue
		}
		c := tools[ref.Adapter]
		if c == nil || c.tools[ref.Tool] == nil || c.adapter.Transport.Type != adapter.TransportHTTP {
			skipped++
			continue
		}
		vars := tmpl.Vars{Params: ref.Params, Env: ref.Env}
		req := &engine.Request{
			Connector: &engine.Connector{
				ID:      ref.Adapter,
				Type:    adapter.TransportHTTP,
				BaseURL: c.adapter.Transport.BaseURL,
				Headers: c.adapter.Transport.Headers,
			},
			Tool: c.tools[ref.Tool],
			Vars: vars,
			HTTP: client,
		}
		if _, err := (rest.Engine{}).Execute(context.Background(), req); err != nil {
			mismatches["execute error"]++
			if mismatches["execute error"] <= examples {
				t.Errorf("%s/%s: the old engine built this request and we refuse it: %v", ref.Adapter, ref.Tool, err)
			}
			continue
		}
		compared++

		for _, d := range diff(ref, cap) {
			if allowed(ref.Adapter, d.kind) {
				expected++
				continue
			}
			mismatches[d.kind]++
			if mismatches[d.kind] <= examples {
				t.Errorf("%s/%s: %s\n  v1: %s\n  go: %s", ref.Adapter, ref.Tool, d.kind, d.want, d.have)
			}
		}
	}

	total := 0
	for _, n := range mismatches {
		total += n
	}
	t.Logf("compared %d requests, skipped %d, %d known divergences, %d differences",
		compared, skipped, expected, total)
	for _, k := range sortedKeys(mismatches) {
		t.Logf("  %-24s %d", k, mismatches[k])
	}
	if compared < 1500 {
		t.Errorf("only %d requests were compared; the fixture or the corpus is not what this test expects", compared)
	}
}

type difference struct{ kind, want, have string }

// diff compares one recorded request with the one just captured.
func diff(ref reference, cap *capture) []difference {
	var out []difference
	add := func(kind, want, have string) {
		if want != have {
			out = append(out, difference{kind, want, have})
		}
	}
	got := cap.req
	add("method", ref.Method, got.Method)

	// A v1 path could carry its own query string, which the recording kept
	// in the URL while the mapped parameters were recorded separately. Both
	// sides end up in one query string on the wire, so compare them that way.
	wantQuery := ref.Query
	if wantURL, err := url.Parse(ref.URL); err == nil {
		add("url", wantURL.Scheme+"://"+wantURL.Host+wantURL.EscapedPath(),
			got.URL.Scheme+"://"+got.URL.Host+got.URL.EscapedPath())
		if wantURL.RawQuery != "" {
			wantQuery = strings.TrimPrefix(wantURL.RawQuery+"&"+ref.Query, "&")
			wantQuery = strings.TrimSuffix(wantQuery, "&")
		}
	}
	add("query", sortQuery(wantQuery), sortQuery(got.URL.RawQuery))

	wantBody, haveBody := normaliseBody(ref.Body), normaliseBody(string(cap.body))
	add("body", wantBody, haveBody)

	for k, want := range ref.Headers {
		if headersNotCompared[k] {
			continue
		}
		// axios carries a default Content-Type on POST even when it sends no
		// body, and that default never reaches the wire.
		if k == "content-type" && wantBody == "" && haveBody == "" {
			continue
		}
		add("header "+k, want, got.Header.Get(k))
	}
	return out
}

func allowed(slug, kind string) bool {
	d, ok := divergences[slug]
	if !ok {
		return false
	}
	for _, k := range d.kinds {
		if k == kind {
			return true
		}
	}
	return false
}

type convertedAdapter struct {
	adapter *adapter.Adapter
	tools   map[string]*adapter.Tool
}

func loadCorpus(t *testing.T) map[string]*convertedAdapter {
	t.Helper()
	files, err := v1.LoadDir(filepath.Join("..", "..", "..", "pkg", "adapter", "v1", "testdata", "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	results, err := v1compat.ConvertAll(files)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*convertedAdapter{}
	for _, r := range results {
		c := &convertedAdapter{adapter: r.Adapter, tools: map[string]*adapter.Tool{}}
		for i := range r.Adapter.Tools {
			c.tools[r.Adapter.Tools[i].Name] = &r.Adapter.Tools[i]
		}
		out[r.Adapter.Metadata.Slug] = c
	}
	return out
}

func loadReferences(t *testing.T) []reference {
	t.Helper()
	path := os.Getenv("PARITY_FIXTURE")
	if path == "" {
		path = filepath.Join("testdata", "v1-requests.json.gz")
	}
	f, err := os.Open(path) //nolint:gosec // a test fixture path
	if err != nil {
		t.Skipf("no parity fixture (%v); regenerate it with scripts/dump-v1-requests.cts", err)
	}
	defer func() { _ = f.Close() }()
	var src io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = zr.Close() }()
		src = zr
	}
	var refs []reference
	if err := json.NewDecoder(src).Decode(&refs); err != nil {
		t.Fatal(err)
	}
	return refs
}

// sortQuery compares query strings as sets of pairs: the engines may order
// parameters differently, but must not encode them differently.
func sortQuery(q string) string {
	if q == "" {
		return ""
	}
	parts := strings.Split(q, "&")
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

// normaliseBody compares JSON bodies by value, form bodies as sets of
// pairs, and anything else verbatim.
func normaliseBody(b string) string {
	trimmed := strings.TrimSpace(b)
	if trimmed == "" || trimmed == "{}" {
		return trimmed
	}
	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err == nil {
		if out, err := json.Marshal(sortKeys(v)); err == nil {
			return string(out)
		}
	}
	if strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "{") {
		return sortQuery(trimmed)
	}
	return trimmed
}

// sortKeys rewrites objects as sorted key/value lists so two encoders that
// disagree about key order still compare equal.
func sortKeys(v any) any {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]any, 0, len(keys)*2)
		for _, k := range keys {
			out = append(out, k, sortKeys(x[k]))
		}
		return out
	case []any:
		for i := range x {
			x[i] = sortKeys(x[i])
		}
		return x
	}
	return v
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
