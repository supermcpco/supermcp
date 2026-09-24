package invoke

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/redis/go-redis/v9"

	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/tool"
)

// cacheKeyVersion is mixed into every key. Bumping it invalidates every
// entry in one move, which is the only safe response to a change in what
// the key covers: an old entry computed under an old rule must never be
// found by a new one.
const cacheKeyVersion = "supermcp/response-cache/v1"

// CacheMode is which backing is serving lookups.
type CacheMode string

const (
	// CacheModeRedis is the shared cache: all replicas see one entry.
	CacheModeRedis CacheMode = "redis"
	// CacheModeMemory is the in-process cache, chosen because no Redis URL
	// was configured.
	CacheModeMemory CacheMode = "memory"
	// CacheModeFallback is the in-process cache, chosen because Redis was
	// configured but is unreachable.
	CacheModeFallback CacheMode = "fallback"
)

// CacheOptions configure a Cache.
type CacheOptions struct {
	// RedisURL is a redis:// or rediss:// URL. Empty selects the in-process
	// backing outright.
	RedisURL string
	// KeyPrefix namespaces the Redis keys. Defaults to "supermcp:rc".
	KeyPrefix string
	// MaxEntries bounds the in-process map. Defaults to 4096.
	MaxEntries int
	// MaxBytes bounds the in-process map by stored size. Defaults to 64 MiB.
	MaxBytes int64
	// MaxEntryBytes is the largest single answer worth keeping. Defaults to
	// 1 MiB. A larger one is served from the upstream every time, which is
	// cheaper than letting one answer own the whole budget.
	MaxEntryBytes int64
	// MaxTTL clamps the adapter's declared cache time. An adapter author
	// picks that number; an operator owns how stale this deployment may
	// get. Defaults to 24h.
	MaxTTL time.Duration
	// RecoverAfter is how long the cache stays on the in-process backing
	// after a Redis error before trying Redis again. Defaults to 5s.
	RecoverAfter time.Duration
	// Now is the clock, injected by tests.
	Now func() time.Time
	// OnDegraded is called on every change of mode, with the error that
	// caused it when there was one. It runs on the request path, so it must
	// not block.
	OnDegraded func(mode CacheMode, err error)
	// Log records the entries that were refused as inconsistent. Nil
	// discards.
	Log *slog.Logger
}

// Cache remembers successful read-only tool results for as long as the
// adapter said they stay true.
//
// Where the rate limiter must never fail open, this must never fail
// *closed onto the wrong answer*: the two are the same discipline pointed
// in opposite directions. Every error path here - an unreachable Redis, a
// malformed entry, a key it cannot build - resolves to a miss, because a
// miss costs one upstream call and a wrong hit costs a customer.
type Cache struct {
	redis  *redisCache
	memory *memoryCache
	now    func() time.Time

	maxTTL        time.Duration
	maxEntryBytes int64

	mode         atomic.Int32
	recoverAfter time.Duration
	// retryRedisAt is a unix-nano deadline before which Redis is not
	// retried, so one outage does not add a round trip to every call.
	retryRedisAt atomic.Int64
	onDegraded   func(CacheMode, error)
	log          *slog.Logger
}

const (
	cacheStateRedis int32 = iota
	cacheStateMemory
	cacheStateFallback
)

type redisCache struct {
	client *redis.Client
	prefix string
}

type memoryCache struct {
	mu sync.Mutex
	// order is oldest-first by insertion, which is also the eviction
	// order. Insertion order and not access order: an entry's usefulness
	// ends when its TTL does, so promoting on read would only keep the
	// popular stale ones alive at the expense of the fresh ones.
	order      *list.List
	entries    map[string]*list.Element
	bytes      int64
	maxEntries int
	maxBytes   int64
}

type memoryEntry struct {
	key     string
	payload []byte
	expires time.Time
	size    int64
}

// cacheEntry is the stored form of one answer. It carries the fingerprint
// of the key it was written under so a reader can prove the entry it found
// is the entry it asked for; see Lookup.
type cacheEntry struct {
	Fingerprint string          `json:"f"`
	OrgID       string          `json:"o"`
	Text        string          `json:"t"`
	Structured  json.RawMessage `json:"s,omitempty"`
	RowCount    int             `json:"r,omitempty"`
	Truncated   bool            `json:"x,omitempty"`
}

// cacheKey is the identity of one cacheable answer.
type cacheKey struct {
	hash  string
	orgID string
	ttl   time.Duration
}

// NewCache builds a Cache. A malformed Redis URL fails the boot; a Redis
// that is merely unreachable does not, because a cache is an optimisation
// and the process must still serve calls without one.
func NewCache(ctx context.Context, opts CacheOptions) (*Cache, error) {
	if opts.KeyPrefix == "" {
		opts.KeyPrefix = "supermcp:rc"
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 4096
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 64 << 20
	}
	if opts.MaxEntryBytes <= 0 {
		opts.MaxEntryBytes = 1 << 20
	}
	if opts.MaxTTL <= 0 {
		opts.MaxTTL = 24 * time.Hour
	}
	if opts.RecoverAfter <= 0 {
		opts.RecoverAfter = 5 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	c := &Cache{
		memory: &memoryCache{
			order:      list.New(),
			entries:    make(map[string]*list.Element),
			maxEntries: opts.MaxEntries,
			maxBytes:   opts.MaxBytes,
		},
		now:           opts.Now,
		maxTTL:        opts.MaxTTL,
		maxEntryBytes: opts.MaxEntryBytes,
		recoverAfter:  opts.RecoverAfter,
		onDegraded:    opts.OnDegraded,
		log:           opts.Log,
	}
	if opts.RedisURL == "" {
		c.mode.Store(cacheStateMemory)
		return c, nil
	}

	ropts, err := redis.ParseURL(opts.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	// Short timeouts: a slow cache must get out of the way of the call it
	// was meant to make faster.
	ropts.DialTimeout = 2 * time.Second
	ropts.ReadTimeout = 250 * time.Millisecond
	ropts.WriteTimeout = 250 * time.Millisecond
	ropts.PoolTimeout = time.Second
	ropts.MaxRetries = 1

	c.redis = &redisCache{client: redis.NewClient(ropts), prefix: opts.KeyPrefix}
	c.mode.Store(cacheStateRedis)

	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := c.redis.client.Ping(pingCtx).Err(); err != nil {
		c.degrade(err)
	}
	return c, nil
}

// Lookup returns the remembered answer for call, if there is one that is
// still inside the window the adapter declared. A nil Cache always misses,
// so the call site needs no guard.
//
// There is no error return on purpose. Nothing a caller could do with a
// cache error differs from what it does with a miss, and an error return
// invites a call site that treats "unknown" as "hit".
//
// A hit is only correct because authorisation happens before this runs:
// the MCP endpoint evaluates tools:invoke for this principal on this tool
// before Execute is entered. The cache therefore never widens who may see
// an answer, only how it is produced.
func (c *Cache) Lookup(ctx context.Context, call Call) (*Result, bool) {
	if c == nil {
		return nil, false
	}
	key, ok := cacheKeyFor(call)
	if !ok {
		return nil, false
	}
	raw, ok := c.get(ctx, key)
	if !ok {
		return nil, false
	}
	var e cacheEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, false
	}
	// The entry restates the key it was written under, and the reader
	// checks it. The key is already a hash over the organisation, so a
	// cross-tenant hit would need a SHA-256 collision; this check means it
	// would need that collision *and* a matching organisation id stored
	// inside the colliding entry. It turns every conceivable failure of the
	// keying - a truncated prefix, a shared Redis database, a future edit
	// that drops a component - into a miss instead of a leak.
	if e.Fingerprint != key.hash ||
		subtle.ConstantTimeCompare([]byte(e.OrgID), []byte(key.orgID)) != 1 {
		if c.log != nil {
			c.log.Error("response cache entry does not match its key, discarding",
				"tool", call.Tool.Name, "org", key.orgID)
		}
		return nil, false
	}

	res := &Result{
		Content: []mcp.Content{&mcp.TextContent{Text: e.Text}},
		// UpstreamDurationMS is deliberately left at zero: no upstream was
		// called, and replaying the original figure would have the metrics
		// report traffic that never left the process.
		Meta: engine.Meta{RowCount: e.RowCount, Truncated: e.Truncated},
	}
	if len(e.Structured) > 0 {
		var s any
		if err := json.Unmarshal(e.Structured, &s); err != nil {
			return nil, false
		}
		res.Structured = s
	}
	return res, true
}

// Store remembers res for the call, if the call is one whose answer may be
// remembered at all. A nil Cache stores nothing.
//
// It declines quietly rather than reporting: there is no failure here that
// the caller should surface to the person who made the tool call.
func (c *Cache) Store(ctx context.Context, call Call, res *Result) {
	if c == nil || res == nil {
		return
	}
	// An upstream refusal is a fact about one moment, not about the
	// resource; caching it would pin a 429 or a 500 in front of every
	// caller for the whole window.
	if res.IsError || res.UpstreamStatus != 0 {
		return
	}
	key, ok := cacheKeyFor(call)
	if !ok {
		return
	}
	// Only the plain text shape round-trips exactly. Binary results are
	// excluded by construction rather than by policy: their content is a
	// link bound to one principal, so a second principal finding it in the
	// cache would receive a URL that answers them with a 404.
	if len(res.Content) != 1 {
		return
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return
	}
	e := cacheEntry{
		Fingerprint: key.hash,
		OrgID:       key.orgID,
		Text:        text.Text,
		RowCount:    res.Meta.RowCount,
		Truncated:   res.Meta.Truncated,
	}
	if res.Structured != nil {
		b, err := json.Marshal(res.Structured)
		if err != nil {
			return
		}
		e.Structured = b
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	if int64(len(raw)) > c.maxEntryBytes {
		return
	}
	ttl := key.ttl
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	c.put(ctx, key, raw, ttl)
}

// Mode reports which backing is serving lookups.
func (c *Cache) Mode() CacheMode {
	if c == nil {
		return CacheModeMemory
	}
	switch c.mode.Load() {
	case cacheStateRedis:
		return CacheModeRedis
	case cacheStateFallback:
		return CacheModeFallback
	default:
		return CacheModeMemory
	}
}

// Degraded reports whether entries are per replica rather than shared.
func (c *Cache) Degraded() bool { return c != nil && c.mode.Load() != cacheStateRedis }

// Close releases the Redis connection pool.
func (c *Cache) Close() error {
	if c == nil || c.redis == nil {
		return nil
	}
	if err := c.redis.client.Close(); err != nil {
		return fmt.Errorf("close redis: %w", err)
	}
	return nil
}

// --- key ------------------------------------------------------------------

// cacheKeyFor builds the key for a call, and reports whether the call may
// be cached at all.
//
// The key covers everything that can change the answer:
//
//   - the organisation, because an entry must never cross a tenant;
//   - the connector and its version, which moves on any edit to the
//     upstream, including a credential being replaced, so a re-pointed or
//     re-keyed connector cannot serve the previous upstream's answers;
//   - the tool and its version, so an edited operation starts clean;
//   - the arguments, canonically encoded;
//   - the caller, whenever the caller can reach the upstream request.
//
// That last one is the one worth arguing about. Upstream credentials in
// this system belong to the connector, not to the person calling it, so
// two callers of the same tool with the same arguments usually send a
// byte-identical request and get a byte-identical answer. Usually is not a
// safety property. A tool may interpolate {{caller.sub}} or
// {{caller.email}} into a path, a query, a header or a SQL statement, and
// then the upstream is answering a question about *that person*; handing
// the result to the next caller is an information leak with the gateway's
// name on it.
//
// So the key narrows to the caller whenever the connector's transport, its
// auth, or the tool definition mentions the caller or request namespaces
// anywhere. The scan is over the serialised documents, so it sees every
// nesting depth, and it fails towards the narrow scope: an unreadable
// document, or one that merely contains the string, narrows. Narrowing
// wrongly costs a cache miss. Widening wrongly costs a customer.
//
// The caller component itself is the digest of callerVars(call) - the
// exact map the template engine is given, and the only route by which the
// caller's identity can reach an upstream. Deriving it from that function
// instead of from a hand-written list means a future field added to
// callerVars is covered on the day it is added rather than on the day
// someone remembers this file.
func cacheKeyFor(call Call) (cacheKey, bool) {
	ttl, ok := cacheable(call)
	if !ok {
		return cacheKey{}, false
	}
	// encoding/json emits object keys in sorted order, so equal arguments
	// encode to equal bytes.
	args, err := json.Marshal(call.Args)
	if err != nil {
		return cacheKey{}, false
	}

	scope, caller := "org", []byte(nil)
	if callerDependent(call) {
		scope, caller = "principal", callerFingerprint(call)
	}

	h := sha256.New()
	for _, part := range [][]byte{
		[]byte(cacheKeyVersion),
		[]byte(call.Connector.OrgID),
		[]byte(call.Connector.ID),
		[]byte(strconv.FormatInt(call.Connector.Version, 10)),
		[]byte(call.Tool.ID),
		[]byte(strconv.FormatInt(call.Tool.Version, 10)),
		[]byte(call.Tool.Name),
		[]byte(scope),
		caller,
		args,
	} {
		writeField(h, part)
	}
	return cacheKey{
		hash:  hex.EncodeToString(h.Sum(nil)),
		orgID: call.Connector.OrgID,
		ttl:   ttl,
	}, true
}

// writeField length-prefixes each component before hashing it. Without
// this, an identifier containing the separator could be split so that two
// different calls produce one key: concatenation is not injective, and a
// cache key that is not injective is a cross-tenant read waiting for the
// right identifier.
func writeField(h hash.Hash, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

// cacheable reports how long a call's answer stays true, and whether it
// may be kept at all. A tool that declares no cache time is never cached:
// silence is not consent, and an adapter author who has not thought about
// staleness has not agreed to any.
func cacheable(call Call) (time.Duration, bool) {
	if call.Connector == nil || call.Tool == nil || call.Tool.Definition == nil {
		return 0, false
	}
	def := call.Tool.Definition
	if def.Response == nil || def.Response.Cache <= 0 {
		return 0, false
	}
	// The same derivation the MCP surface advertises, so what is cached
	// agrees with what clients were told the tool does.
	ann := tool.Derive(def, call.Connector.Transport.Type, call.Connector.ReadOnly)
	if !ann.ReadOnlyHint || ann.DestructiveHint {
		return 0, false
	}
	return time.Duration(def.Response.Cache), true
}

// callerDependent reports whether anything about the caller can reach the
// upstream request. See cacheKeyFor for why this decides the key's scope.
func callerDependent(call Call) bool {
	for _, doc := range []any{call.Tool.Definition, call.Connector.Transport, call.Connector.Auth} {
		b, err := json.Marshal(doc)
		if err != nil {
			// A document that cannot be read cannot be cleared.
			return true
		}
		if bytes.Contains(b, []byte("caller.")) || bytes.Contains(b, []byte("req.")) {
			return true
		}
	}
	return false
}

// callerFingerprint digests the caller variables this call would render
// with.
func callerFingerprint(call Call) []byte {
	vars := callerVars(call)
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	h := sha256.New()
	for _, k := range keys {
		writeField(h, []byte(k))
		writeField(h, []byte(vars[k]))
	}
	return h.Sum(nil)
}

// --- backings --------------------------------------------------------------

func (c *Cache) get(ctx context.Context, key cacheKey) ([]byte, bool) {
	if err := ctx.Err(); err != nil {
		return nil, false
	}
	now := c.now()
	if c.useRedis(now) {
		raw, err := c.redis.get(ctx, key)
		if err == nil {
			c.recover()
			return raw, raw != nil
		}
		c.degrade(err)
	}
	return c.memory.get(key.hash, now)
}

func (c *Cache) put(ctx context.Context, key cacheKey, raw []byte, ttl time.Duration) {
	if err := ctx.Err(); err != nil {
		return
	}
	now := c.now()
	if c.useRedis(now) {
		err := c.redis.put(ctx, key, raw, ttl)
		if err == nil {
			c.recover()
			return
		}
		c.degrade(err)
	}
	c.memory.put(key.hash, raw, now.Add(ttl))
}

// get returns the stored bytes, a nil slice for a miss, or an error when
// Redis itself is the problem.
func (r *redisCache) get(ctx context.Context, key cacheKey) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	raw, err := r.client.Get(ctx, r.prefix+":"+key.hash).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis cache get: %w", err)
	}
	return raw, nil
}

func (r *redisCache) put(ctx context.Context, key cacheKey, raw []byte, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	if err := r.client.Set(ctx, r.prefix+":"+key.hash, raw, ttl).Err(); err != nil {
		return fmt.Errorf("redis cache set: %w", err)
	}
	return nil
}

func (m *memoryCache) get(key string, now time.Time) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.entries[key]
	if !ok {
		return nil, false
	}
	e, _ := el.Value.(*memoryEntry)
	if !now.Before(e.expires) {
		m.removeLocked(el)
		return nil, false
	}
	return e.payload, true
}

func (m *memoryCache) put(key string, raw []byte, expires time.Time) {
	size := int64(len(key) + len(raw))
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.entries[key]; ok {
		m.removeLocked(old)
	}
	// An entry that alone exceeds the budget would evict the whole cache
	// and then not fit; refuse it instead.
	if size > m.maxBytes {
		return
	}
	for len(m.entries) >= m.maxEntries || m.bytes+size > m.maxBytes {
		oldest := m.order.Front()
		if oldest == nil {
			return
		}
		m.removeLocked(oldest)
	}
	e := &memoryEntry{key: key, payload: raw, expires: expires, size: size}
	m.entries[key] = m.order.PushBack(e)
	m.bytes += size
}

func (m *memoryCache) removeLocked(el *list.Element) {
	e, _ := el.Value.(*memoryEntry)
	m.order.Remove(el)
	delete(m.entries, e.key)
	m.bytes -= e.size
}

// useRedis reports whether this call should try Redis. After a failure the
// cache waits out RecoverAfter, so an outage costs one probe per window
// rather than a timeout per tool call.
func (c *Cache) useRedis(now time.Time) bool {
	if c.redis == nil {
		return false
	}
	if c.mode.Load() == cacheStateRedis {
		return true
	}
	return now.UnixNano() >= c.retryRedisAt.Load()
}

func (c *Cache) degrade(err error) {
	c.retryRedisAt.Store(c.now().Add(c.recoverAfter).UnixNano())
	if c.mode.Swap(cacheStateFallback) != cacheStateFallback && c.onDegraded != nil {
		c.onDegraded(CacheModeFallback, err)
	}
}

func (c *Cache) recover() {
	if c.mode.Swap(cacheStateRedis) != cacheStateRedis && c.onDegraded != nil {
		c.onDegraded(CacheModeRedis, nil)
	}
}
