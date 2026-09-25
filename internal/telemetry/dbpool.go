package telemetry

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Database pool names. The pools are fixed by the process, not by
// anything an operator or a tenant creates, so the label stays at two
// values; any other name is recorded as OtherLabel.
const (
	PoolApp   = "app"
	PoolMaint = "maint"
)

// DBPoolStats is one reading of a connection pool. It carries plain
// numbers so this package needs nothing from the driver; the caller
// copies them out of whatever its pool reports.
type DBPoolStats struct {
	// Acquired, Idle and Total are connections right now; Max is the
	// ceiling Acquired can reach.
	Acquired, Idle, Total, Max int32
	// Acquires counts every successful acquire since the pool opened.
	Acquires int64
	// EmptyAcquires counts the acquires that found no idle connection and
	// had to wait for one to be released or built.
	EmptyAcquires int64
	// EmptyAcquireWait is the total time those acquires spent waiting.
	EmptyAcquireWait time.Duration
}

// dbPoolCollector reads the pools at scrape time. A pool's statistics are
// a handful of atomic loads, so there is nothing to be gained by sampling
// them on a timer and a stale reading to be lost.
type dbPoolCollector struct {
	acquired, idle, total, maxConns *prometheus.Desc
	acquires, emptyAcquires         *prometheus.Desc
	emptyWait                       *prometheus.Desc

	// mu guards pools, which WatchDBPool writes once at start-up and
	// Collect reads on every scrape.
	mu    sync.RWMutex
	pools map[string]func() DBPoolStats
}

func newDBPoolCollector() *dbPoolCollector {
	desc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(prometheus.BuildFQName(Namespace, "db_pool", name), help, []string{"pool"}, nil)
	}
	return &dbPoolCollector{
		acquired:      desc("acquired_connections", "Connections checked out of the pool right now."),
		idle:          desc("idle_connections", "Open connections waiting in the pool."),
		total:         desc("total_connections", "Open connections, acquired, idle and being built."),
		maxConns:      desc("max_connections", "The most connections the pool will open."),
		acquires:      desc("acquires_total", "Successful acquires from the pool."),
		emptyAcquires: desc("empty_acquires_total", "Acquires that found no idle connection and had to wait."),
		emptyWait:     desc("empty_acquire_wait_seconds_total", "Time spent waiting by acquires that found the pool empty."),
		pools:         make(map[string]func() DBPoolStats, 2),
	}
}

// WatchDBPool publishes a connection pool's statistics under
// supermcp_db_pool_*{pool=name}. stat is called on every scrape, so it
// must be cheap and must not block. Watching a name twice replaces the
// first.
func (m *Metrics) WatchDBPool(name string, stat func() DBPoolStats) {
	if m == nil || stat == nil {
		return
	}
	m.dbPools.mu.Lock()
	defer m.dbPools.mu.Unlock()
	m.dbPools.pools[oneOf(name, PoolApp, PoolMaint)] = stat
}

// Describe implements prometheus.Collector.
func (c *dbPoolCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.acquired, c.idle, c.total, c.maxConns, c.acquires, c.emptyAcquires, c.emptyWait} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *dbPoolCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for name, stat := range c.pools {
		s := stat()
		ch <- prometheus.MustNewConstMetric(c.acquired, prometheus.GaugeValue, float64(s.Acquired), name)
		ch <- prometheus.MustNewConstMetric(c.idle, prometheus.GaugeValue, float64(s.Idle), name)
		ch <- prometheus.MustNewConstMetric(c.total, prometheus.GaugeValue, float64(s.Total), name)
		ch <- prometheus.MustNewConstMetric(c.maxConns, prometheus.GaugeValue, float64(s.Max), name)
		ch <- prometheus.MustNewConstMetric(c.acquires, prometheus.CounterValue, float64(s.Acquires), name)
		ch <- prometheus.MustNewConstMetric(c.emptyAcquires, prometheus.CounterValue, float64(s.EmptyAcquires), name)
		ch <- prometheus.MustNewConstMetric(c.emptyWait, prometheus.CounterValue, s.EmptyAcquireWait.Seconds(), name)
	}
}
