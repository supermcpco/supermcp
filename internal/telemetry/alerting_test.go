package telemetry_test

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/supermcpco/supermcp/internal/telemetry"
)

// The series the chart's alert rules read. Each test pins the values a
// rule depends on and the ceiling on how many series the metric can grow
// to, because a label that can take any value is the one that takes the
// scrape down.

func TestKEKOperationsCountByOutcome(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	m := telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg})

	m.ObserveKEK(telemetry.KEKProviderAWSKMS, telemetry.KEKKeyActive, telemetry.KEKUnwrap, nil)
	m.ObserveKEK(telemetry.KEKProviderAWSKMS, telemetry.KEKKeyActive, telemetry.KEKUnwrap, errors.New("kms: connection refused"))
	m.ObserveKEK(telemetry.KEKProviderAWSKMS, telemetry.KEKKeyActive, telemetry.KEKUnwrap, errors.New("kms: connection refused"))
	m.ObserveKEK(telemetry.KEKProviderAWSKMS, telemetry.KEKKeyActive, telemetry.KEKWrap, nil)
	m.ObserveKEK(telemetry.KEKProviderLocal, telemetry.KEKKeyActive, telemetry.KEKWrap, nil)
	// During a move both keys are awskms; the role is what tells the old
	// key failing apart from the new one.
	m.ObserveKEK(telemetry.KEKProviderAWSKMS, telemetry.KEKKeyPrevious, telemetry.KEKUnwrap, errors.New("AccessDeniedException"))

	tests := []struct {
		provider, key, op, outcome string
		want                       float64
	}{
		{"awskms", "active", "unwrap", "ok", 1},
		{"awskms", "active", "unwrap", "error", 2},
		{"awskms", "active", "wrap", "ok", 1},
		{"local", "active", "wrap", "ok", 1},
		{"awskms", "previous", "unwrap", "error", 1},
	}
	for _, tc := range tests {
		got := value(t, reg, "supermcp_kek_operations_total",
			map[string]string{"provider": tc.provider, "key": tc.key, "op": tc.op, "outcome": tc.outcome})
		if got != tc.want {
			t.Errorf("kek_operations_total{%s,%s,%s,%s} = %v, want %v", tc.provider, tc.key, tc.op, tc.outcome, got, tc.want)
		}
	}
}

func TestKEKOperationsCardinalityIsFixed(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	m := telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg})

	// Every provider, role and op a caller could invent, each with both
	// outcomes.
	for _, provider := range []string{"awskms", "local", "gcpkms", "", "awskms:eu-west-1/alias/x"} {
		for _, key := range []string{"active", "previous", "awskms:eu-west-1/alias/old", ""} {
			for _, op := range []string{"wrap", "unwrap", "rewrap", ""} {
				m.ObserveKEK(provider, key, op, nil)
				m.ObserveKEK(provider, key, op, errors.New("x"))
			}
		}
	}
	// provider, key and op each three values with other, outcome ok|error.
	if got, limit := seriesCount(t, reg, "supermcp_kek_operations_total"), 3*3*3*2; got > limit {
		t.Errorf("kek_operations_total has %d series, want at most %d", got, limit)
	}
	if got := value(t, reg, "supermcp_kek_operations_total",
		map[string]string{"provider": "other", "key": "other", "op": "other", "outcome": "error"}); got != 12 {
		t.Errorf("unknown providers, keys and ops recorded %v errors under other/other/other, want 12", got)
	}
}

func TestAuditExportLagTakesTheWorstPerKind(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	m := telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg})

	m.SetAuditExportLag(map[string]time.Duration{
		"webhook":  20 * time.Minute,
		"splunk":   0,
		"carrier":  3 * time.Minute, // not a kind this build knows
		"pigeon":   7 * time.Minute,
		"syslog":   90 * time.Second,
		"otlp":     0,
		"":         time.Minute,
		"webhook2": time.Second,
	})
	want := map[string]float64{"webhook": 1200, "syslog": 90, "splunk": 0, "otlp": 0, "other": 420}
	for kind, v := range want {
		if got := value(t, reg, "supermcp_audit_export_lag_seconds", map[string]string{"kind": kind}); got != v {
			t.Errorf("audit_export_lag_seconds{kind=%q} = %v, want %v", kind, got, v)
		}
	}
	if got := seriesCount(t, reg, "supermcp_audit_export_lag_seconds"); got != len(want) {
		t.Errorf("audit_export_lag_seconds has %d series, want %d", got, len(want))
	}

	// Everything caught up, and the webhook destination switched off: no
	// kind may keep reporting the lag it had.
	m.SetAuditExportLag(map[string]time.Duration{"syslog": 0})
	for kind := range want {
		if got := value(t, reg, "supermcp_audit_export_lag_seconds", map[string]string{"kind": kind}); got != 0 {
			t.Errorf("after catching up, audit_export_lag_seconds{kind=%q} = %v, want 0", kind, got)
		}
	}
}

func TestDBPoolStatsAreReadAtScrape(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	m := telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg})

	// Nothing watched yet: the collector is registered and publishes nothing.
	if got := seriesCount(t, reg, "supermcp_db_pool_acquired_connections"); got != 0 {
		t.Fatalf("with no pool watched there are %d series, want 0", got)
	}

	app := telemetry.DBPoolStats{Acquired: 9, Idle: 1, Total: 10, Max: 10, Acquires: 100, EmptyAcquires: 4, EmptyAcquireWait: 1500 * time.Millisecond}
	m.WatchDBPool(telemetry.PoolApp, func() telemetry.DBPoolStats { return app })
	m.WatchDBPool(telemetry.PoolMaint, func() telemetry.DBPoolStats { return telemetry.DBPoolStats{Max: 4, Idle: 2, Total: 2} })
	m.WatchDBPool("tenant_42", func() telemetry.DBPoolStats { return telemetry.DBPoolStats{Max: 1} })

	tests := []struct {
		metric, pool string
		want         float64
	}{
		{"supermcp_db_pool_acquired_connections", "app", 9},
		{"supermcp_db_pool_idle_connections", "app", 1},
		{"supermcp_db_pool_total_connections", "app", 10},
		{"supermcp_db_pool_max_connections", "app", 10},
		{"supermcp_db_pool_acquires_total", "app", 100},
		{"supermcp_db_pool_empty_acquires_total", "app", 4},
		{"supermcp_db_pool_empty_acquire_wait_seconds_total", "app", 1.5},
		{"supermcp_db_pool_max_connections", "maint", 4},
		{"supermcp_db_pool_acquired_connections", "maint", 0},
		{"supermcp_db_pool_max_connections", "other", 1},
	}
	for _, tc := range tests {
		if got := value(t, reg, tc.metric, map[string]string{"pool": tc.pool}); got != tc.want {
			t.Errorf("%s{pool=%q} = %v, want %v", tc.metric, tc.pool, got, tc.want)
		}
	}
	if got := seriesCount(t, reg, "supermcp_db_pool_max_connections"); got != 3 {
		t.Errorf("db_pool_max_connections has %d series, want app, maint and other", got)
	}

	// The reading is taken at scrape time, not when the pool was watched.
	app.Acquired = 3
	if got := value(t, reg, "supermcp_db_pool_acquired_connections", map[string]string{"pool": "app"}); got != 3 {
		t.Errorf("after the pool changed, acquired = %v, want 3", got)
	}
}

// The session gauge is one series per replica, and the close counter has
// a fixed set of reasons: a server id or session id as a label would give
// every client a series of its own.
func TestMCPSessionSeriesAreBounded(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	m := telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg})

	m.SetMCPSessions(3)
	m.SetMCPSessions(2)
	for _, reason := range []string{"idle", "idle", "capacity", "client", "shutdown", "gone", "srv_123", "", "a session id"} {
		m.ObserveMCPSessionClosed(reason)
	}

	if got := value(t, reg, "supermcp_mcp_sessions", map[string]string{}); got != 2 {
		t.Errorf("mcp_sessions = %v, want 2", got)
	}
	want := map[string]float64{"idle": 2, "capacity": 1, "client": 1, "shutdown": 1, "gone": 1, "other": 3}
	for reason, n := range want {
		if got := value(t, reg, "supermcp_mcp_sessions_closed_total", map[string]string{"reason": reason}); got != n {
			t.Errorf("mcp_sessions_closed_total{reason=%q} = %v, want %v", reason, got, n)
		}
	}
	if n := len(family(t, reg, "supermcp_mcp_sessions_closed_total").GetMetric()); n != len(want) {
		t.Errorf("mcp_sessions_closed_total has %d series, want %d", n, len(want))
	}
}
