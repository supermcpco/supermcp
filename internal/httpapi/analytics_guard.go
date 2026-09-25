package httpapi

import (
	"sync"
	"time"
)

// The usage analytics run their aggregates on the app pool, the same pool
// that records every tool call. The guard below keeps one workspace from
// holding that pool: it answers repeated questions from memory, and it
// refuses a workspace's third query while two are still running rather
// than queueing it behind them.

const (
	// usageInflightPerOrg is how many analytics queries one workspace
	// may have running on this replica at once.
	usageInflightPerOrg = 2
	// usageCacheTTL is how long an answer is reused. The screen asks for
	// windows that end on a whole minute, so its refreshes within that
	// minute are served from here.
	usageCacheTTL = 60 * time.Second
	// usageCacheMax bounds the cache. Past it, expired entries are swept,
	// and if none have expired the new answer is not kept.
	usageCacheMax = 1024
)

// usageKey is everything an answer depends on. The organisation is part
// of it, so one workspace is never served another's figures.
type usageKey struct {
	org      string
	from, to int64
	bucket   string
	by       string
	limit    int
}

type usageCached struct {
	rep     usageReport
	expires time.Time
}

// analyticsGuard is the per-replica concurrency cap and result cache for
// the usage analytics. Its zero value is not usable; newAnalyticsGuard
// makes one.
type analyticsGuard struct {
	now func() time.Time

	mu       sync.Mutex
	inflight map[string]int
	cache    map[usageKey]usageCached
}

func newAnalyticsGuard(now func() time.Time) *analyticsGuard {
	if now == nil {
		now = time.Now
	}
	return &analyticsGuard{now: now, inflight: map[string]int{}, cache: map[usageKey]usageCached{}}
}

// acquire takes one of the organisation's query slots. It reports false,
// taking nothing, when both are in use.
func (g *analyticsGuard) acquire(org string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inflight[org] >= usageInflightPerOrg {
		return false
	}
	g.inflight[org]++
	return true
}

// release returns a slot taken by acquire. An organisation with nothing
// running is removed, so the map holds only workspaces that are querying.
func (g *analyticsGuard) release(org string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inflight[org] <= 1 {
		delete(g.inflight, org)
		return
	}
	g.inflight[org]--
}

func (g *analyticsGuard) get(k usageKey) (usageReport, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, ok := g.cache[k]
	if !ok {
		return usageReport{}, false
	}
	if !g.now().Before(c.expires) {
		delete(g.cache, k)
		return usageReport{}, false
	}
	return c.rep, true
}

func (g *analyticsGuard) put(k usageKey, rep usageReport) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if len(g.cache) >= usageCacheMax {
		for key, c := range g.cache {
			if !now.Before(c.expires) {
				delete(g.cache, key)
			}
		}
		if len(g.cache) >= usageCacheMax {
			return
		}
	}
	g.cache[k] = usageCached{rep: rep, expires: now.Add(usageCacheTTL)}
}
