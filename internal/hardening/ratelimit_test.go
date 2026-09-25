package hardening_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/hardening"
)

// clock is the injected time source. Every timing assertion here is
// deterministic; nothing in this file sleeps.
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

// call is one expected request: advance the clock, then charge the budget
// once and check the verdict.
type call struct {
	advance       time.Duration
	wantAllowed   bool
	wantRemaining int
}

// scenario holds only behaviour both backings share. The Redis backing is
// a sliding window and the memory backing is a token bucket, so they
// disagree part way through a window; they agree on the burst, on refusal
// inside the window and on full recovery after one whole window, which is
// what a budget actually promises.
type scenario struct {
	name  string
	limit hardening.Limit
	calls []call
}

func scenarios() []scenario {
	minute := time.Minute
	return []scenario{
		{
			name:  "burst fits",
			limit: hardening.Limit{Name: "burst_fits", Burst: 3, Window: minute},
			calls: []call{
				{wantAllowed: true, wantRemaining: 2},
				{wantAllowed: true, wantRemaining: 1},
				{wantAllowed: true, wantRemaining: 0},
			},
		},
		{
			name:  "one over the burst is refused",
			limit: hardening.Limit{Name: "burst_over", Burst: 3, Window: minute},
			calls: []call{
				{wantAllowed: true, wantRemaining: 2},
				{wantAllowed: true, wantRemaining: 1},
				{wantAllowed: true, wantRemaining: 0},
				{wantAllowed: false, wantRemaining: 0},
			},
		},
		{
			name:  "window boundary",
			limit: hardening.Limit{Name: "boundary", Burst: 2, Window: minute},
			calls: []call{
				{wantAllowed: true, wantRemaining: 1},
				{wantAllowed: true, wantRemaining: 0},
				// Not quite half a window: neither backing has room yet.
				{advance: 29 * time.Second, wantAllowed: false, wantRemaining: 0},
				// One whole window after the first call, plus a
				// millisecond so the boundary is unambiguous.
				{advance: 31*time.Second + time.Millisecond, wantAllowed: true, wantRemaining: 1},
				{wantAllowed: true, wantRemaining: 0},
				{wantAllowed: false, wantRemaining: 0},
			},
		},
		{
			name:  "exceeding then waiting recovers",
			limit: hardening.Limit{Name: "recovers", Burst: 5, Window: minute},
			calls: []call{
				{wantAllowed: true, wantRemaining: 4},
				{wantAllowed: true, wantRemaining: 3},
				{wantAllowed: true, wantRemaining: 2},
				{wantAllowed: true, wantRemaining: 1},
				{wantAllowed: true, wantRemaining: 0},
				{wantAllowed: false, wantRemaining: 0},
				{advance: minute + time.Millisecond, wantAllowed: true, wantRemaining: 4},
				{wantAllowed: true, wantRemaining: 3},
			},
		},
		{
			name:  "a single-request budget",
			limit: hardening.Limit{Name: "single", Burst: 1, Window: 10 * time.Second},
			calls: []call{
				{wantAllowed: true, wantRemaining: 0},
				{wantAllowed: false, wantRemaining: 0},
				{advance: 10*time.Second + time.Millisecond, wantAllowed: true, wantRemaining: 0},
			},
		},
	}
}

func runScenario(t *testing.T, l *hardening.Limiter, c *clock, s scenario, key string) {
	t.Helper()
	ctx := context.Background()
	for i, want := range s.calls {
		if want.advance > 0 {
			c.advance(want.advance)
		}
		got, err := l.Allow(ctx, key, s.limit)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if got.Allowed != want.wantAllowed {
			t.Errorf("call %d: allowed = %v, want %v", i, got.Allowed, want.wantAllowed)
		}
		if got.Remaining != want.wantRemaining {
			t.Errorf("call %d: remaining = %d, want %d", i, got.Remaining, want.wantRemaining)
		}
		if got.Limit != s.limit.Burst {
			t.Errorf("call %d: limit = %d, want %d", i, got.Limit, s.limit.Burst)
		}
		if !got.Allowed && got.RetryAfter <= 0 {
			t.Errorf("call %d: refused with RetryAfter %v, want a positive wait", i, got.RetryAfter)
		}
		if got.Allowed && got.RetryAfter != 0 {
			t.Errorf("call %d: allowed with RetryAfter %v, want zero", i, got.RetryAfter)
		}
	}
}

func TestLimiterMemory(t *testing.T) {
	t.Parallel()
	for _, s := range scenarios() {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			c := newClock()
			l, err := hardening.New(t.Context(), hardening.Options{Now: c.Now})
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			t.Cleanup(func() { _ = l.Close() })
			if l.Mode() != hardening.ModeMemory {
				t.Fatalf("mode = %q, want %q", l.Mode(), hardening.ModeMemory)
			}
			runScenario(t, l, c, s, "ip:198.51.100.7")
		})
	}
}

// TestLimiterRedis runs the same table against a real Redis when one is
// offered. It is skipped otherwise: the suite must not need a server.
func TestLimiterRedis(t *testing.T) {
	t.Parallel()
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}
	prefix := "supermcp:rltest:" + strconv.FormatInt(time.Now().UnixNano(), 36)
	for _, s := range scenarios() {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			c := newClock()
			l, err := hardening.New(t.Context(), hardening.Options{
				RedisURL:  url,
				KeyPrefix: prefix,
				Now:       c.Now,
			})
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			t.Cleanup(func() { _ = l.Close() })
			if l.Mode() != hardening.ModeRedis {
				t.Fatalf("mode = %q, want %q; is REDIS_URL reachable?", l.Mode(), hardening.ModeRedis)
			}
			runScenario(t, l, c, s, "ip:198.51.100.7")
		})
	}
}

func TestBudgetsAreIndependentPerIdentityAndRoute(t *testing.T) {
	t.Parallel()
	c := newClock()
	l, err := hardening.New(t.Context(), hardening.Options{Now: c.Now})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	signIn := hardening.Limit{Name: "signin", Burst: 1, Window: time.Minute}
	tools := hardening.Limit{Name: "tool_call", Burst: 1, Window: time.Minute}

	mustAllow(t, l, "ip:a", signIn, true)
	mustAllow(t, l, "ip:a", signIn, false)
	// A different route has its own budget for the same identity.
	mustAllow(t, l, "ip:a", tools, true)
	// A different identity has its own budget for the same route.
	mustAllow(t, l, "ip:b", signIn, true)
}

func TestDegradedDividesByExpectedReplicas(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		replicas      int
		burst         int
		wantEffective int
	}{
		{name: "one replica keeps the whole budget", replicas: 1, burst: 8, wantEffective: 8},
		{name: "four replicas take a quarter each", replicas: 4, burst: 8, wantEffective: 2},
		{name: "uneven division rounds down", replicas: 3, burst: 8, wantEffective: 2},
		{name: "never below one request per window", replicas: 5, burst: 2, wantEffective: 1},
		{name: "zero replicas is read as one", replicas: 0, burst: 4, wantEffective: 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newClock()
			l, err := hardening.New(t.Context(), hardening.Options{
				ExpectedReplicas: tc.replicas,
				Now:              c.Now,
			})
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			t.Cleanup(func() { _ = l.Close() })

			limit := hardening.Limit{Name: "divided", Burst: tc.burst, Window: time.Minute}
			ctx := t.Context()
			for i := range tc.wantEffective {
				d, err := l.Allow(ctx, "ip:198.51.100.9", limit)
				if err != nil {
					t.Fatalf("call %d: %v", i, err)
				}
				if !d.Allowed {
					t.Fatalf("call %d of %d refused, want allowed", i+1, tc.wantEffective)
				}
				if d.Limit != tc.wantEffective {
					t.Fatalf("call %d: limit = %d, want %d", i, d.Limit, tc.wantEffective)
				}
				if !d.Degraded {
					t.Errorf("call %d: Degraded = false, want true on the memory backing", i)
				}
			}
			d, err := l.Allow(ctx, "ip:198.51.100.9", limit)
			if err != nil {
				t.Fatalf("allow: %v", err)
			}
			if d.Allowed {
				t.Fatalf("call %d allowed, want refused past the divided budget", tc.wantEffective+1)
			}
		})
	}
}

// TestUnreachableRedisDoesNotFallOpen is the point of the whole file: the
// system this replaces allowed everything when Redis was gone.
func TestUnreachableRedisDoesNotFallOpen(t *testing.T) {
	t.Parallel()
	c := newClock()
	var (
		mu    sync.Mutex
		modes []hardening.Mode
	)
	l, err := hardening.New(t.Context(), hardening.Options{
		RedisURL:         "redis://" + deadAddr(t),
		ExpectedReplicas: 2,
		Now:              c.Now,
		OnDegraded: func(m hardening.Mode, _ error) {
			mu.Lock()
			defer mu.Unlock()
			modes = append(modes, m)
		},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if l.Mode() != hardening.ModeFallback {
		t.Fatalf("mode = %q, want %q", l.Mode(), hardening.ModeFallback)
	}
	if !l.Degraded() {
		t.Error("Degraded() = false, want true with Redis unreachable")
	}
	mu.Lock()
	got := append([]hardening.Mode(nil), modes...)
	mu.Unlock()
	if len(got) != 1 || got[0] != hardening.ModeFallback {
		t.Errorf("OnDegraded saw %v, want one %q", got, hardening.ModeFallback)
	}

	// Budget 6 over 2 expected replicas is 3 per replica, and the seventh
	// call must still be refused rather than waved through.
	limit := hardening.Limit{Name: "fallback", Burst: 6, Window: time.Minute}
	for i := range 3 {
		mustAllowAt(t, l, "ip:203.0.113.4", limit, true, i)
	}
	mustAllowAt(t, l, "ip:203.0.113.4", limit, false, 3)
}

func TestAllowRejectsAnUnusableBudget(t *testing.T) {
	t.Parallel()
	l, err := hardening.New(t.Context(), hardening.Options{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	tests := []struct {
		name  string
		limit hardening.Limit
	}{
		{name: "no name", limit: hardening.Limit{Burst: 1, Window: time.Minute}},
		{name: "no burst", limit: hardening.Limit{Name: "x", Window: time.Minute}},
		{name: "no window", limit: hardening.Limit{Name: "x", Burst: 1}},
		{name: "negative burst", limit: hardening.Limit{Name: "x", Burst: -1, Window: time.Minute}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d, err := l.Allow(t.Context(), "ip:a", tc.limit)
			if err == nil {
				t.Fatal("Allow returned no error for an unusable budget")
			}
			if d.Allowed {
				t.Error("Allow returned an error and allowed the call")
			}
		})
	}
}

func TestNewRejectsAMalformedRedisURL(t *testing.T) {
	t.Parallel()
	if _, err := hardening.New(t.Context(), hardening.Options{RedisURL: "http://not-redis"}); err == nil {
		t.Fatal("New accepted a non-redis URL")
	}
}

func TestIdentity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		principal *authz.Principal
		remote    string
		want      string
	}{
		{name: "anonymous falls back to the address", remote: "198.51.100.1:51234", want: "ip:198.51.100.1"},
		{
			name:      "an anonymous principal is still the address",
			principal: &authz.Principal{Kind: authz.KindAnonymous, ID: "nobody"},
			remote:    "198.51.100.2:443",
			want:      "ip:198.51.100.2",
		},
		{
			name:      "a user is keyed by id",
			principal: &authz.Principal{Kind: authz.KindUser, ID: "usr_1"},
			remote:    "198.51.100.3:443",
			want:      "user:usr_1",
		},
		{
			name:      "an api key is keyed by the key, not its owner",
			principal: &authz.Principal{Kind: authz.KindAPIKey, ID: "usr_1", APIKeyID: "key_9"},
			remote:    "198.51.100.4:443",
			want:      "key:key_9",
		},
		{
			name:   "an address with no port is used whole",
			remote: "198.51.100.5",
			want:   "ip:198.51.100.5",
		},
		{
			name:   "ipv6 loses its port",
			remote: "[2001:db8::1]:443",
			want:   "ip:2001:db8::1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/api/v1/whatever", nil)
			r.RemoteAddr = tc.remote
			if tc.principal != nil {
				r = r.WithContext(authz.WithPrincipal(r.Context(), tc.principal))
			}
			if got := hardening.Identity(r); got != tc.want {
				t.Errorf("Identity = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDecisionSetHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		d    hardening.Decision
		want map[string]string
	}{
		{
			name: "allowed carries no Retry-After",
			d: hardening.Decision{
				Allowed: true, Limit: 10, Remaining: 4, ResetAfter: 1500 * time.Millisecond,
			},
			want: map[string]string{
				"RateLimit-Limit": "10", "RateLimit-Remaining": "4",
				"RateLimit-Reset": "2", "Retry-After": "",
			},
		},
		{
			name: "refused rounds the wait up to a whole second",
			d: hardening.Decision{
				Limit: 10, Remaining: 0, ResetAfter: 30 * time.Second, RetryAfter: 1200 * time.Millisecond,
			},
			want: map[string]string{
				"RateLimit-Limit": "10", "RateLimit-Remaining": "0",
				"RateLimit-Reset": "30", "Retry-After": "2",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := http.Header{}
			tc.d.SetHeaders(h)
			for k, want := range tc.want {
				if got := h.Get(k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestBoundedLimiter(t *testing.T) {
	t.Parallel()
	l, err := hardening.New(t.Context(), hardening.Options{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	b := l.Bounded(hardening.Limit{Name: "dcr", Burst: 2, Window: time.Hour})
	for i := range 2 {
		if !b.Allow("ip:a") {
			t.Fatalf("registration %d of 2 was refused", i+1)
		}
	}
	if b.Allow("ip:a") {
		t.Error("the third registration was allowed past a budget of two")
	}
	if !b.Allow("ip:b") {
		t.Error("a second address was refused on the first registration")
	}
}

func TestDefaultBudgets(t *testing.T) {
	t.Parallel()
	b := hardening.DefaultBudgets()
	for _, l := range []hardening.Limit{b.SignIn, b.Register, b.Invite, b.DCR, b.ToolCall, b.API} {
		if l.Name == "" || l.Burst <= 0 || l.Window <= 0 {
			t.Errorf("default budget %+v is unusable", l)
		}
	}
	if b.SignIn.Name == b.ToolCall.Name {
		t.Error("two default budgets share a name, so they would share a counter")
	}
}

func mustAllow(t *testing.T, l *hardening.Limiter, key string, limit hardening.Limit, want bool) {
	t.Helper()
	mustAllowAt(t, l, key, limit, want, -1)
}

func mustAllowAt(t *testing.T, l *hardening.Limiter, key string, limit hardening.Limit, want bool, i int) {
	t.Helper()
	d, err := l.Allow(t.Context(), key, limit)
	if err != nil {
		t.Fatalf("allow %s on %s: %v", key, limit.Name, err)
	}
	if d.Allowed != want {
		t.Fatalf("allow %s on %s (call %d) = %v, want %v", key, limit.Name, i, d.Allowed, want)
	}
}

// deadAddr returns an address nothing is listening on, by taking a port
// and giving it straight back.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}
