package invoke_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/invoke"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// clock is the injected time source; nothing in this file sleeps.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// callSpec is the shape of one tool call, with only the fields that can
// move a cache key.
type callSpec struct {
	orgID       string
	connectorID string
	connVersion int64
	toolID      string
	toolName    string
	toolVersion int64
	principalID string
	apiKeyID    string
	serverID    string
	args        map[string]any
	method      string
	cache       adapter.Duration
	// path carries the operation path, which is where a template reaches
	// the caller namespace.
	path        string
	destructive bool
}

func (s callSpec) build() invoke.Call {
	def := &adapter.Tool{
		Name:      or(s.toolName, "list_things"),
		Operation: adapter.Operation{Method: or(s.method, "GET"), Path: or(s.path, "/things")},
		Response:  &adapter.Response{Cache: s.cache},
	}
	if s.cache == 0 {
		def.Response = nil
	}
	if s.destructive {
		yes := true
		def.Annotations = &adapter.Annotations{DestructiveHint: &yes}
	}
	orgID := or(s.orgID, "org-a")
	return invoke.Call{
		Principal: &authz.Principal{
			Kind: authz.KindUser, ID: or(s.principalID, "user-1"),
			OrgID: orgID, APIKeyID: s.apiKeyID, AuthMethod: "session",
		},
		ServerID: s.serverID,
		Connector: &connector.Connector{
			ID: or(s.connectorID, "conn-1"), OrgID: orgID,
			Transport: adapter.Transport{Type: adapter.TransportHTTP},
			Version:   orInt(s.connVersion, 1),
		},
		Tool: &connector.Tool{
			ID: or(s.toolID, "tool-1"), Name: def.Name,
			Definition: def, Version: orInt(s.toolVersion, 1),
		},
		Args: s.args,
	}
}

func or(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func orInt(v, fallback int64) int64 {
	if v == 0 {
		return fallback
	}
	return v
}

func textResult(text string) *invoke.Result {
	return &invoke.Result{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func newCache(t *testing.T, c *clock, opts invoke.CacheOptions) *invoke.Cache {
	t.Helper()
	opts.Now = c.Now
	cache, err := invoke.NewCache(t.Context(), opts)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	return cache
}

func mustHit(t *testing.T, cache *invoke.Cache, call invoke.Call, want string) {
	t.Helper()
	res, ok := cache.Lookup(t.Context(), call)
	if !ok {
		t.Fatal("wanted a hit, got a miss")
	}
	text, isText := res.Content[0].(*mcp.TextContent)
	if !isText || text.Text != want {
		t.Fatalf("hit carried %#v, want text %q", res.Content[0], want)
	}
}

func mustMiss(t *testing.T, cache *invoke.Cache, call invoke.Call) {
	t.Helper()
	if _, ok := cache.Lookup(t.Context(), call); ok {
		t.Fatal("wanted a miss, got a hit")
	}
}

func TestCacheWindow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		advance time.Duration
		wantHit bool
	}{
		{name: "inside the window", advance: 29 * time.Second, wantHit: true},
		{name: "on the last instant of the window", advance: 30*time.Second - time.Nanosecond, wantHit: true},
		{name: "one tick past the window", advance: 30 * time.Second, wantHit: false},
		{name: "long after the window", advance: time.Hour, wantHit: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			clk := newClock()
			cache := newCache(t, clk, invoke.CacheOptions{})
			call := callSpec{cache: adapter.Duration(30 * time.Second)}.build()

			cache.Store(t.Context(), call, textResult("first answer"))
			clk.advance(tc.advance)

			if tc.wantHit {
				mustHit(t, cache, call, "first answer")
				return
			}
			mustMiss(t, cache, call)
		})
	}
}

// TestCacheNeverCrossesATenant is the assertion this whole file exists
// for. Every field that could plausibly be confused for a tenant boundary
// is held identical between the two calls, so the only thing keeping them
// apart is the organisation in the key.
func TestCacheNeverCrossesATenant(t *testing.T) {
	t.Parallel()
	clk := newClock()
	cache := newCache(t, clk, invoke.CacheOptions{})

	ttl := adapter.Duration(time.Hour)
	// Same connector id, same tool id, same tool name, same versions, same
	// principal id, same arguments. Only the organisation differs, and in
	// a real deployment even the ids would not collide; they do here so
	// that the test fails if the organisation ever leaves the key.
	victim := callSpec{
		orgID: "org-victim", connectorID: "conn-shared", toolID: "tool-shared",
		principalID: "user-1", args: map[string]any{"id": "42"}, cache: ttl,
	}.build()
	attacker := callSpec{
		orgID: "org-attacker", connectorID: "conn-shared", toolID: "tool-shared",
		principalID: "user-1", args: map[string]any{"id": "42"}, cache: ttl,
	}.build()

	cache.Store(t.Context(), victim, textResult("the victim's salary export"))

	if res, ok := cache.Lookup(t.Context(), attacker); ok {
		text, _ := res.Content[0].(*mcp.TextContent)
		t.Fatalf("another organisation read a cached answer: %q", text.Text)
	}
	mustHit(t, cache, victim, "the victim's salary export")

	// And the other direction: the attacker's own entry must not become
	// the victim's answer either.
	cache.Store(t.Context(), attacker, textResult("poisoned"))
	mustHit(t, cache, victim, "the victim's salary export")
	mustHit(t, cache, attacker, "poisoned")
}

// TestCacheScope pins when an entry is shared across an organisation and
// when it narrows to one caller.
func TestCacheScope(t *testing.T) {
	t.Parallel()
	ttl := adapter.Duration(time.Hour)
	tests := []struct {
		name    string
		first   callSpec
		second  callSpec
		wantHit bool
	}{
		{
			name:    "a caller-independent tool is shared inside the organisation",
			first:   callSpec{principalID: "user-1", cache: ttl},
			second:  callSpec{principalID: "user-2", cache: ttl},
			wantHit: true,
		},
		{
			name:    "a path that names the caller narrows to the caller",
			first:   callSpec{principalID: "user-1", path: "/users/{{caller.sub}}/inbox", cache: ttl},
			second:  callSpec{principalID: "user-2", path: "/users/{{caller.sub}}/inbox", cache: ttl},
			wantHit: false,
		},
		{
			name:    "the same caller of a caller-dependent tool still hits",
			first:   callSpec{principalID: "user-1", path: "/users/{{caller.email}}", cache: ttl},
			second:  callSpec{principalID: "user-1", path: "/users/{{caller.email}}", cache: ttl},
			wantHit: true,
		},
		{
			// Two keys of one user render the same caller variables, so the
			// upstream request is byte-identical and the answer is the same
			// answer. The key follows what reaches the wire, not what the
			// credential happened to be called.
			name:    "two api keys of one user share an answer",
			first:   callSpec{principalID: "user-1", apiKeyID: "key-a", path: "/me/{{caller.sub}}", cache: ttl},
			second:  callSpec{principalID: "user-1", apiKeyID: "key-b", path: "/me/{{caller.sub}}", cache: ttl},
			wantHit: true,
		},
		{
			name:    "a server-bound call is not shared with another server",
			first:   callSpec{serverID: "srv-a", path: "/x/{{caller.server}}", cache: ttl},
			second:  callSpec{serverID: "srv-b", path: "/x/{{caller.server}}", cache: ttl},
			wantHit: false,
		},
		{
			name:    "different arguments are different answers",
			first:   callSpec{args: map[string]any{"page": 1}, cache: ttl},
			second:  callSpec{args: map[string]any{"page": 2}, cache: ttl},
			wantHit: false,
		},
		{
			name:    "a connector edit retires the previous answers",
			first:   callSpec{connVersion: 1, cache: ttl},
			second:  callSpec{connVersion: 2, cache: ttl},
			wantHit: false,
		},
		{
			name:    "a tool edit retires the previous answers",
			first:   callSpec{toolVersion: 1, cache: ttl},
			second:  callSpec{toolVersion: 2, cache: ttl},
			wantHit: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cache := newCache(t, newClock(), invoke.CacheOptions{})
			cache.Store(t.Context(), tc.first.build(), textResult("answer"))
			if tc.wantHit {
				mustHit(t, cache, tc.second.build(), "answer")
				return
			}
			mustMiss(t, cache, tc.second.build())
		})
	}
}

// TestCacheRefusals covers the results that must never be remembered at
// all, whatever the key says.
func TestCacheRefusals(t *testing.T) {
	t.Parallel()
	ttl := adapter.Duration(time.Hour)
	tests := []struct {
		name string
		spec callSpec
		res  *invoke.Result
	}{
		{
			name: "no declared cache time",
			spec: callSpec{},
			res:  textResult("answer"),
		},
		{
			name: "a destructive tool",
			spec: callSpec{cache: ttl, method: "POST", toolName: "delete_account", destructive: true},
			res:  textResult("answer"),
		},
		{
			name: "a writing method without an explicit read-only hint",
			spec: callSpec{cache: ttl, method: "DELETE", toolName: "remove_thing"},
			res:  textResult("answer"),
		},
		{
			name: "an errored result",
			spec: callSpec{cache: ttl},
			res:  &invoke.Result{Content: []mcp.Content{&mcp.TextContent{Text: "boom"}}, IsError: true},
		},
		{
			name: "an upstream refusal shown as content",
			spec: callSpec{cache: ttl},
			res:  &invoke.Result{Content: []mcp.Content{&mcp.TextContent{Text: "429"}}, UpstreamStatus: 429},
		},
		{
			name: "content that is not plain text",
			spec: callSpec{cache: ttl},
			res: &invoke.Result{Content: []mcp.Content{
				&mcp.ResourceLink{URI: "https://example.test/api/v1/blobs/abc"},
			}},
		},
		{
			name: "a result larger than one entry may be",
			spec: callSpec{cache: ttl},
			res:  textResult(strings.Repeat("x", 2<<20)),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cache := newCache(t, newClock(), invoke.CacheOptions{})
			call := tc.spec.build()
			cache.Store(t.Context(), call, tc.res)
			mustMiss(t, cache, call)
		})
	}
}

// TestCacheEvictsOldestFirstUnderTheByteBound fills a cache far smaller
// than the answers it is offered and checks that the memory it holds stays
// bounded and that the survivor is the newest.
func TestCacheEvictsOldestFirstUnderTheByteBound(t *testing.T) {
	t.Parallel()
	clk := newClock()
	// Two answers of ~1 KiB fit; a third must push the first out.
	cache := newCache(t, clk, invoke.CacheOptions{MaxBytes: 2500, MaxEntries: 100})

	ttl := adapter.Duration(time.Hour)
	body := strings.Repeat("x", 1000)
	calls := make([]invoke.Call, 3)
	for i := range calls {
		calls[i] = callSpec{toolID: "tool-" + string(rune('a'+i)), cache: ttl}.build()
		cache.Store(t.Context(), calls[i], textResult(body+string(rune('a'+i))))
		clk.advance(time.Second)
	}

	mustMiss(t, cache, calls[0])
	mustHit(t, cache, calls[1], body+"b")
	mustHit(t, cache, calls[2], body+"c")
}

func TestCacheEvictsUnderTheEntryBound(t *testing.T) {
	t.Parallel()
	clk := newClock()
	cache := newCache(t, clk, invoke.CacheOptions{MaxEntries: 2})

	ttl := adapter.Duration(time.Hour)
	calls := make([]invoke.Call, 3)
	for i := range calls {
		calls[i] = callSpec{toolID: "tool-" + string(rune('a'+i)), cache: ttl}.build()
		cache.Store(t.Context(), calls[i], textResult("answer"))
		clk.advance(time.Second)
	}

	mustMiss(t, cache, calls[0])
	mustHit(t, cache, calls[1], "answer")
	mustHit(t, cache, calls[2], "answer")
}

func TestCacheStructuredOutputSurvives(t *testing.T) {
	t.Parallel()
	cache := newCache(t, newClock(), invoke.CacheOptions{})
	call := callSpec{cache: adapter.Duration(time.Hour)}.build()

	cache.Store(t.Context(), call, &invoke.Result{
		Content:    []mcp.Content{&mcp.TextContent{Text: "answer"}},
		Structured: map[string]any{"total": 3.0},
	})
	res, ok := cache.Lookup(t.Context(), call)
	if !ok {
		t.Fatal("wanted a hit, got a miss")
	}
	structured, isMap := res.Structured.(map[string]any)
	if !isMap || structured["total"] != 3.0 {
		t.Fatalf("structured output came back as %#v", res.Structured)
	}
	// No upstream was called, so none may be reported.
	if res.Meta.UpstreamDurationMS != 0 {
		t.Fatalf("a cache hit reported %dms of upstream time", res.Meta.UpstreamDurationMS)
	}
}

func TestCacheClampsTheDeclaredWindow(t *testing.T) {
	t.Parallel()
	clk := newClock()
	cache := newCache(t, clk, invoke.CacheOptions{MaxTTL: time.Minute})
	call := callSpec{cache: adapter.Duration(30 * 24 * time.Hour)}.build()

	cache.Store(t.Context(), call, textResult("answer"))
	clk.advance(59 * time.Second)
	mustHit(t, cache, call, "answer")
	clk.advance(2 * time.Second)
	mustMiss(t, cache, call)
}

func TestNilCacheIsAlwaysAMiss(t *testing.T) {
	t.Parallel()
	var cache *invoke.Cache
	call := callSpec{cache: adapter.Duration(time.Hour)}.build()
	cache.Store(t.Context(), call, textResult("answer"))
	if _, ok := cache.Lookup(t.Context(), call); ok {
		t.Fatal("a nil cache returned a hit")
	}
	if cache.Mode() != invoke.CacheModeMemory {
		t.Fatalf("a nil cache reports mode %q", cache.Mode())
	}
}

func TestNewCacheRejectsANonRedisURL(t *testing.T) {
	t.Parallel()
	if _, err := invoke.NewCache(t.Context(), invoke.CacheOptions{RedisURL: "http://not-redis"}); err == nil {
		t.Fatal("NewCache accepted a non-redis URL")
	}
}
