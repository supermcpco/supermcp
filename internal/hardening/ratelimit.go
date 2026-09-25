// Package hardening holds the request-path defences that belong to no one
// feature: rate limiting today, CSP nonces and redaction next.
package hardening

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/supermcpco/supermcp/internal/authz"
)

// Limit is one route's budget: Burst requests per Window, counted per
// identity. Name namespaces the counter, so the sign-in budget and the
// tool-call budget never draw on each other for the same caller.
type Limit struct {
	Name   string
	Burst  int
	Window time.Duration
}

// Budgets are the starting budgets for the routes that need different
// shapes of traffic. They are values, not globals: the operator overrides
// them from configuration and passes the result to the middleware.
type Budgets struct {
	// SignIn covers password sign-in and password reset, where the threat
	// is credential stuffing rather than volume.
	SignIn Limit
	// Register covers self-service registration.
	Register Limit
	// Invite covers looking up and accepting an organisation invite, which
	// is reachable without a credential and can create an account.
	Invite Limit
	// DCR covers RFC 7591 dynamic client registration, which writes a row
	// per call and is reachable without a credential.
	DCR Limit
	// ToolCall covers MCP tools/call, the one hot path here.
	ToolCall Limit
	// Analytics covers the usage analytics, whose every request runs
	// aggregates over up to 90 days on the pool that records tool calls.
	Analytics Limit
	// API covers the rest of the admin API.
	API Limit
}

// Decision is the outcome of one Allow, shaped for the RateLimit headers
// of draft-ietf-httpapi-ratelimit-headers.
type Decision struct {
	Allowed bool
	// Limit is the budget actually applied, already divided by the
	// expected replica count when the limiter is degraded.
	Limit     int
	Remaining int
	// ResetAfter is how long until the full budget is available again.
	ResetAfter time.Duration
	// RetryAfter is how long until one more request would be allowed. It
	// is zero when the request was allowed.
	RetryAfter time.Duration
	// Degraded is true when this decision came from the in-memory backing,
	// so the budget is per replica rather than shared.
	Degraded bool
}

// Mode is which backing is serving decisions.
type Mode string

const (
	// ModeRedis is the shared sliding window: one budget for all replicas.
	ModeRedis Mode = "redis"
	// ModeMemory is the in-memory token bucket, chosen because no Redis
	// URL was configured.
	ModeMemory Mode = "memory"
	// ModeFallback is the in-memory token bucket, chosen because Redis was
	// configured but is unreachable.
	ModeFallback Mode = "fallback"
)

// Options configure a Limiter.
type Options struct {
	// RedisURL is a redis:// or rediss:// URL. Empty selects the in-memory
	// backing outright.
	RedisURL string
	// ExpectedReplicas is how many replicas share the intended ceiling.
	// The in-memory backing divides every budget by it so N replicas
	// together stay near that ceiling instead of serving N times it.
	// Defaults to 1.
	ExpectedReplicas int
	// KeyPrefix namespaces the Redis keys. Defaults to "supermcp:rl".
	KeyPrefix string
	// MaxKeys bounds the in-memory bucket map. Defaults to 100000.
	MaxKeys int
	// RecoverAfter is how long the limiter stays on the in-memory backing
	// after a Redis error before trying Redis again. Defaults to 5s.
	RecoverAfter time.Duration
	// Now is the clock, injected by tests.
	Now func() time.Time
	// OnDegraded is called on every change of mode, with the error that
	// caused it when there was one. It runs on the request path, so it
	// must not block: set a gauge, write a log line, queue an event.
	OnDegraded func(mode Mode, err error)
}

// Limiter enforces per-identity budgets. It prefers a Redis sliding window
// so replicas share one budget, and falls back to an in-memory token
// bucket when Redis is absent or unreachable. It never falls open: the
// fallback divides each budget by the expected replica count and reports
// itself degraded, because a limiter that stops limiting during an outage
// is decorative.
type Limiter struct {
	redis  *redisBacking
	memory *memoryBacking
	now    func() time.Time

	mode         atomic.Int32
	recoverAfter time.Duration
	// retryRedisAt is a unix-nano deadline before which Redis is not
	// retried, so one outage does not add a round trip to every request.
	retryRedisAt atomic.Int64
	onDegraded   func(Mode, error)
}

const (
	stateRedis int32 = iota
	stateMemory
	stateFallback
)

type redisBacking struct {
	client *redis.Client
	script *redis.Script
	prefix string
	// member makes every window entry unique across replicas and calls;
	// two requests in the same millisecond must not collapse into one
	// sorted-set member.
	instance string
	seq      atomic.Uint64
}

type memoryBacking struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	divisor int
	maxKeys int
}

type bucket struct {
	tokens float64
	last   time.Time
}

// slidingWindowSrc trims the window, admits the call when there is room
// and reports what is left. It is one round trip and it is atomic, which
// is the whole reason the shared budget lives in Redis.
const slidingWindowSrc = `
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local count = redis.call('ZCARD', KEYS[1])
local allowed = 0
if count < limit then
  redis.call('ZADD', KEYS[1], now, ARGV[4])
  count = count + 1
  allowed = 1
end
redis.call('PEXPIRE', KEYS[1], window)
local reset = window
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
if oldest[2] ~= nil then
  reset = (tonumber(oldest[2]) + window) - now
  if reset < 0 then reset = 0 end
end
local remaining = limit - count
if remaining < 0 then remaining = 0 end
return {allowed, remaining, reset}
`

// DefaultBudgets returns the starting budgets. Sign-in and registration
// are deliberately small and long-windowed: they are attacked slowly. Tool
// calls are large and short-windowed: they are legitimate traffic.
func DefaultBudgets() Budgets {
	return Budgets{
		SignIn:    Limit{Name: "signin", Burst: 10, Window: time.Minute},
		Register:  Limit{Name: "register", Burst: 5, Window: time.Hour},
		Invite:    Limit{Name: "invite", Burst: 5, Window: time.Hour},
		DCR:       Limit{Name: "dcr", Burst: 10, Window: time.Hour},
		ToolCall:  Limit{Name: "tool_call", Burst: 600, Window: time.Minute},
		Analytics: Limit{Name: "analytics", Burst: 30, Window: time.Minute},
		API:       Limit{Name: "api", Burst: 300, Window: time.Minute},
	}
}

// New builds a Limiter. A malformed Redis URL is a configuration error and
// fails the boot; a Redis that is merely unreachable is not, because the
// process must still start and still limit.
func New(ctx context.Context, opts Options) (*Limiter, error) {
	if opts.ExpectedReplicas < 1 {
		opts.ExpectedReplicas = 1
	}
	if opts.MaxKeys <= 0 {
		opts.MaxKeys = 100_000
	}
	if opts.RecoverAfter <= 0 {
		opts.RecoverAfter = 5 * time.Second
	}
	if opts.KeyPrefix == "" {
		opts.KeyPrefix = "supermcp:rl"
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	l := &Limiter{
		memory: &memoryBacking{
			buckets: make(map[string]*bucket),
			divisor: opts.ExpectedReplicas,
			maxKeys: opts.MaxKeys,
		},
		now:          opts.Now,
		recoverAfter: opts.RecoverAfter,
		onDegraded:   opts.OnDegraded,
	}
	if opts.RedisURL == "" {
		l.mode.Store(stateMemory)
		return l, nil
	}

	ropts, err := redis.ParseURL(opts.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	// Short timeouts and one retry: a slow Redis must degrade the limiter,
	// not the request it is protecting.
	ropts.DialTimeout = 2 * time.Second
	ropts.ReadTimeout = 250 * time.Millisecond
	ropts.WriteTimeout = 250 * time.Millisecond
	ropts.PoolTimeout = time.Second
	ropts.MaxRetries = 1

	id, err := instanceID()
	if err != nil {
		return nil, err
	}
	l.redis = &redisBacking{
		client:   redis.NewClient(ropts),
		script:   redis.NewScript(slidingWindowSrc),
		prefix:   opts.KeyPrefix,
		instance: id,
	}
	l.mode.Store(stateRedis)

	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := l.redis.client.Ping(pingCtx).Err(); err != nil {
		l.degrade(err)
	}
	return l, nil
}

// Allow charges one request against key's budget. An error means the
// budget itself is unusable; the caller should treat it as a refusal,
// never as permission.
func (l *Limiter) Allow(ctx context.Context, key string, limit Limit) (Decision, error) {
	if limit.Name == "" || limit.Burst <= 0 || limit.Window <= 0 {
		return Decision{}, errors.New("rate limit budget needs a name, a positive burst and a positive window")
	}
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	now := l.now()
	if l.useRedis(now) {
		d, err := l.redis.allow(ctx, key, limit, now)
		if err == nil {
			l.recover()
			return d, nil
		}
		// Not an error to the caller: the request still gets a verdict,
		// from a budget that is smaller rather than absent.
		l.degrade(err)
	}
	d := l.memory.allow(limit.Name+":"+key, limit, now)
	d.Degraded = true
	return d, nil
}

// Mode reports which backing is serving decisions.
func (l *Limiter) Mode() Mode {
	switch l.mode.Load() {
	case stateRedis:
		return ModeRedis
	case stateFallback:
		return ModeFallback
	default:
		return ModeMemory
	}
}

// Degraded reports whether budgets are per replica rather than shared.
func (l *Limiter) Degraded() bool { return l.mode.Load() != stateRedis }

// Close releases the Redis connection pool.
func (l *Limiter) Close() error {
	if l.redis == nil {
		return nil
	}
	if err := l.redis.client.Close(); err != nil {
		return fmt.Errorf("close redis: %w", err)
	}
	return nil
}

// Bounded adapts the limiter to the context-free Allow(key) bool interface
// the OAuth server uses for dynamic client registration.
func (l *Limiter) Bounded(limit Limit) *BoundedLimiter {
	return &BoundedLimiter{limiter: l, limit: limit}
}

// BoundedLimiter is a Limiter with its budget fixed, exposing the
// synchronous Allow(key) bool that mcpauth.ClientLimiter expects.
type BoundedLimiter struct {
	limiter *Limiter
	limit   Limit
}

// Allow reports whether key may proceed. The interface carries no context,
// so one is derived here with a deadline short enough that a stalled Redis
// cannot hold the request.
func (b *BoundedLimiter) Allow(key string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d, err := b.limiter.Allow(ctx, key, b.limit)
	return err == nil && d.Allowed
}

// SetHeaders writes the standard rate limit headers, and Retry-After when
// the request was refused.
func (d Decision) SetHeaders(h http.Header) {
	h.Set("RateLimit-Limit", strconv.Itoa(d.Limit))
	h.Set("RateLimit-Remaining", strconv.Itoa(d.Remaining))
	h.Set("RateLimit-Reset", strconv.Itoa(ceilSeconds(d.ResetAfter)))
	if !d.Allowed {
		h.Set("Retry-After", strconv.Itoa(ceilSeconds(d.RetryAfter)))
	}
}

// Identity returns the key a request is limited by: the principal when the
// request carries one, otherwise the client address. An unauthenticated
// flood is the case a limiter exists for, so anonymous traffic must still
// land in a bucket rather than in none.
//
// The address comes from RemoteAddr alone. X-Forwarded-For is attacker
// controlled unless a trusted proxy rewrites it, and a spoofable identity
// is a free bypass; a proxy-aware middleware must normalise RemoteAddr
// before this runs.
func Identity(r *http.Request) string {
	if p, ok := authz.From(r.Context()); ok && p.Kind != authz.KindAnonymous {
		switch {
		case p.APIKeyID != "":
			return "key:" + p.APIKeyID
		case p.ID != "":
			return string(p.Kind) + ":" + p.ID
		}
	}
	return "ip:" + clientAddr(r.RemoteAddr)
}

func (r *redisBacking) allow(ctx context.Context, key string, limit Limit, now time.Time) (Decision, error) {
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	nowMS := now.UnixMilli()
	windowMS := limit.Window.Milliseconds()
	member := strconv.FormatInt(nowMS, 36) + "-" + r.instance + "-" + strconv.FormatUint(r.seq.Add(1), 36)

	raw, err := r.script.Run(ctx, r.client,
		[]string{r.prefix + ":" + limit.Name + ":" + key},
		nowMS, windowMS, limit.Burst, member).Slice()
	if err != nil {
		return Decision{}, fmt.Errorf("redis sliding window: %w", err)
	}
	if len(raw) != 3 {
		return Decision{}, fmt.Errorf("redis sliding window returned %d values, want 3", len(raw))
	}
	allowed, ok1 := raw[0].(int64)
	remaining, ok2 := raw[1].(int64)
	resetMS, ok3 := raw[2].(int64)
	if !ok1 || !ok2 || !ok3 {
		return Decision{}, errors.New("redis sliding window returned a non-integer value")
	}
	d := Decision{
		Allowed:    allowed == 1,
		Limit:      limit.Burst,
		Remaining:  int(remaining),
		ResetAfter: time.Duration(resetMS) * time.Millisecond,
	}
	if !d.Allowed {
		d.RetryAfter = d.ResetAfter
	}
	return d, nil
}

func (m *memoryBacking) allow(key string, limit Limit, now time.Time) Decision {
	effective := m.effective(limit.Burst)
	capacity := float64(effective)
	rate := capacity / limit.Window.Seconds()

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.buckets[key]; !ok && len(m.buckets) >= m.maxKeys {
		m.evictLocked(now, limit.Window)
	}
	b, ok := m.buckets[key]
	if !ok {
		b = &bucket{tokens: capacity, last: now}
		m.buckets[key] = b
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() * rate
		b.last = now
	}
	if b.tokens > capacity {
		b.tokens = capacity
	}

	d := Decision{Limit: effective}
	if b.tokens >= 1 {
		b.tokens--
		d.Allowed = true
	} else {
		d.RetryAfter = spanFor(1-b.tokens, rate)
	}
	d.Remaining = int(b.tokens)
	d.ResetAfter = spanFor(capacity-b.tokens, rate)
	return d
}

// effective divides the configured budget across the replicas expected to
// share it. Rounding down would let a 3-replica deployment of a budget of
// 2 refuse everything, so the floor is one request per window.
func (m *memoryBacking) effective(burst int) int {
	n := burst / m.divisor
	if n < 1 {
		return 1
	}
	return n
}

// evictLocked keeps the bucket map bounded. Buckets idle for a whole
// window are full again, so dropping them changes no verdict. If none are
// idle, this many identities are active at once, which is a distributed
// flood rather than one noisy caller: the least recently seen half goes,
// because an unbounded map turns the limiter into the outage.
func (m *memoryBacking) evictLocked(now time.Time, window time.Duration) {
	for k, b := range m.buckets {
		if now.Sub(b.last) >= window {
			delete(m.buckets, k)
		}
	}
	if len(m.buckets) < m.maxKeys {
		return
	}
	seen := make([]int64, 0, len(m.buckets))
	for _, b := range m.buckets {
		seen = append(seen, b.last.UnixNano())
	}
	slices.Sort(seen)
	cutoff := seen[len(seen)/2]
	for k, b := range m.buckets {
		if b.last.UnixNano() <= cutoff {
			delete(m.buckets, k)
		}
	}
}

// useRedis reports whether this call should try Redis. After a failure the
// limiter waits out RecoverAfter, so an outage costs one probe per window
// rather than a timeout per request.
func (l *Limiter) useRedis(now time.Time) bool {
	if l.redis == nil {
		return false
	}
	if l.mode.Load() == stateRedis {
		return true
	}
	return now.UnixNano() >= l.retryRedisAt.Load()
}

func (l *Limiter) degrade(err error) {
	l.retryRedisAt.Store(l.now().Add(l.recoverAfter).UnixNano())
	if l.mode.Swap(stateFallback) != stateFallback && l.onDegraded != nil {
		l.onDegraded(ModeFallback, err)
	}
}

func (l *Limiter) recover() {
	if l.mode.Swap(stateRedis) != stateRedis && l.onDegraded != nil {
		l.onDegraded(ModeRedis, nil)
	}
}

func instanceID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate limiter instance id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func spanFor(tokens, rate float64) time.Duration {
	if tokens <= 0 || rate <= 0 {
		return 0
	}
	return time.Duration(tokens / rate * float64(time.Second))
}

func ceilSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int((d + time.Second - 1) / time.Second)
}

func clientAddr(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}
