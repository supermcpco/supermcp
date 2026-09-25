package telemetry_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/supermcpco/supermcp/internal/telemetry"
)

func TestInstrumentNamesAndLabels(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	m := telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg, PerTool: true})

	m.ObserveToolCall("http", "stripe_create_charge", telemetry.StatusSuccess, telemetry.ClassNone, 120*time.Millisecond)
	m.ObserveUpstream("http", 80*time.Millisecond)
	m.ObserveMCPRequest("tools/call", http.MethodPost, http.StatusOK)
	m.ObserveHTTPRequest("/api/v1/connectors/{id}", http.MethodGet, http.StatusOK)
	m.ObserveSurfaceBuild(3 * time.Millisecond)
	m.SetBreakerState("conn_1", telemetry.BreakerOpen)
	m.SetAuditQueueDepth(7)
	m.SetRateLimitDegraded(true)
	m.ObserveCacheInvalidation(telemetry.CacheAuthz, telemetry.InvalidationNotify)
	m.SetCacheListenerConnected(true)

	tests := []struct {
		name       string
		metric     string
		wantLabels []string
	}{
		{name: "tool calls", metric: "supermcp_tool_calls_total", wantLabels: []string{"connector_type", "error_class", "status"}},
		{name: "tool call duration", metric: "supermcp_tool_call_duration_seconds", wantLabels: []string{"connector_type"}},
		{name: "per-tool calls", metric: "supermcp_tool_calls_by_tool_total", wantLabels: []string{"connector_type", "status", "tool"}},
		{name: "upstream duration", metric: "supermcp_upstream_duration_seconds", wantLabels: []string{"connector_type"}},
		{name: "mcp requests", metric: "supermcp_mcp_requests_total", wantLabels: []string{"code", "endpoint", "method"}},
		{name: "http requests", metric: "supermcp_http_requests_total", wantLabels: []string{"code", "method", "route"}},
		{name: "surface build", metric: "supermcp_surface_build_seconds", wantLabels: []string{}},
		{name: "breaker state", metric: "supermcp_breaker_state", wantLabels: []string{"connector"}},
		{name: "audit queue depth", metric: "supermcp_audit_queue_depth", wantLabels: []string{}},
		{name: "ratelimit degraded", metric: "supermcp_ratelimit_degraded", wantLabels: []string{}},
		{name: "cache invalidations", metric: "supermcp_cache_invalidations_total", wantLabels: []string{"cache", "source"}},
		{name: "cache listener", metric: "supermcp_cache_listener_connected", wantLabels: []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := labelNames(t, reg, tc.metric)
			if !slices.Equal(got, tc.wantLabels) {
				t.Errorf("%s labels = %v, want %v", tc.metric, got, tc.wantLabels)
			}
		})
	}
}

func TestGaugesCarryTheValueSet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		record func(*telemetry.Metrics)
		metric string
		labels map[string]string
		want   float64
	}{
		{
			name:   "breaker open",
			record: func(m *telemetry.Metrics) { m.SetBreakerState("conn_1", telemetry.BreakerOpen) },
			metric: "supermcp_breaker_state",
			labels: map[string]string{"connector": "conn_1"},
			want:   2,
		},
		{
			name:   "breaker closed",
			record: func(m *telemetry.Metrics) { m.SetBreakerState("conn_1", telemetry.BreakerClosed) },
			metric: "supermcp_breaker_state",
			labels: map[string]string{"connector": "conn_1"},
			want:   0,
		},
		{
			name:   "audit queue depth",
			record: func(m *telemetry.Metrics) { m.SetAuditQueueDepth(42) },
			metric: "supermcp_audit_queue_depth",
			want:   42,
		},
		{
			// The writer reports a running total; the counter follows it
			// and never goes back down.
			name: "audit events dropped",
			record: func(m *telemetry.Metrics) {
				m.SetAuditDroppedTotal(3)
				m.SetAuditDroppedTotal(5)
				m.SetAuditDroppedTotal(4)
			},
			metric: "supermcp_audit_events_dropped_total",
			want:   5,
		},
		{
			name:   "ratelimit degraded",
			record: func(m *telemetry.Metrics) { m.SetRateLimitDegraded(true) },
			metric: "supermcp_ratelimit_degraded",
			want:   1,
		},
		{
			name:   "ratelimit healthy",
			record: func(m *telemetry.Metrics) { m.SetRateLimitDegraded(false) },
			metric: "supermcp_ratelimit_degraded",
			want:   0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := prometheus.NewRegistry()
			m := telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg})
			tc.record(m)
			if got := value(t, reg, tc.metric, tc.labels); got != tc.want {
				t.Errorf("%s = %v, want %v", tc.metric, got, tc.want)
			}
		})
	}
}

func TestPerToolSeriesAreOffByDefault(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	m := telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg})
	m.ObserveToolCall("http", "stripe_create_charge", telemetry.StatusSuccess, telemetry.ClassNone, time.Millisecond)

	if n := seriesCount(t, reg, "supermcp_tool_calls_by_tool_total"); n != 0 {
		t.Errorf("per-tool series = %d, want 0 with the opt-in off", n)
	}
	// The aggregate still counts the call; only the attribution is absent.
	if got := value(t, reg, "supermcp_tool_calls_total", map[string]string{
		"connector_type": "http", "status": "success", "error_class": "none",
	}); got != 1 {
		t.Errorf("tool calls total = %v, want 1", got)
	}
}

func TestPerToolCapCollapsesIntoOther(t *testing.T) {
	t.Parallel()
	// A cap of three makes the overflow visible without a long loop.
	const perToolCap = 3
	reg := prometheus.NewRegistry()
	m := telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg, PerTool: true, PerToolCap: perToolCap})

	for i := range 10 {
		m.ObserveToolCall("http", "tool_"+strconv.Itoa(i), telemetry.StatusSuccess, telemetry.ClassNone, time.Millisecond)
	}
	// A name admitted before the cap keeps its own series afterwards.
	m.ObserveToolCall("http", "tool_0", telemetry.StatusSuccess, telemetry.ClassNone, time.Millisecond)

	// Three named tools plus the overflow bucket, and the seven names that
	// arrived after the cap all land in it.
	want := strings.NewReader(`
# HELP supermcp_tool_calls_by_tool_total Tool calls by tool name, capped and collapsed into _other past the cap.
# TYPE supermcp_tool_calls_by_tool_total counter
supermcp_tool_calls_by_tool_total{connector_type="http",status="success",tool="_other"} 7
supermcp_tool_calls_by_tool_total{connector_type="http",status="success",tool="tool_0"} 2
supermcp_tool_calls_by_tool_total{connector_type="http",status="success",tool="tool_1"} 1
supermcp_tool_calls_by_tool_total{connector_type="http",status="success",tool="tool_2"} 1
`)
	if err := testutil.GatherAndCompare(reg, want, "supermcp_tool_calls_by_tool_total"); err != nil {
		t.Error(err)
	}
	// Nothing is lost in the aggregate.
	if got := value(t, reg, "supermcp_tool_calls_total", map[string]string{
		"connector_type": "http", "status": "success", "error_class": "none",
	}); got != 11 {
		t.Errorf("tool calls total = %v, want 11", got)
	}
}

func TestLabelsAreNormalised(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		connectorType string
		status        telemetry.CallStatus
		class         telemetry.ErrorClass
		wantType      string
		wantStatus    string
		wantClass     string
	}{
		{
			name: "known values pass through", connectorType: "database",
			status: telemetry.StatusTimeout, class: telemetry.ClassTimeout,
			wantType: "database", wantStatus: "timeout", wantClass: "timeout",
		},
		{
			name: "an unknown error class is bucketed", connectorType: "http",
			status: telemetry.StatusError, class: telemetry.ErrorClass("connection reset by 10.0.0.4"),
			wantType: "http", wantStatus: "error", wantClass: "other",
		},
		{
			name: "an unknown status is read as an error", connectorType: "graphql",
			status: telemetry.CallStatus("weird"), class: telemetry.ClassInternal,
			wantType: "graphql", wantStatus: "error", wantClass: "internal",
		},
		{
			name:   "an empty connector type is not an empty label",
			status: telemetry.StatusSuccess, class: telemetry.ClassNone,
			wantType: "unknown", wantStatus: "success", wantClass: "none",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := prometheus.NewRegistry()
			m := telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg})
			m.ObserveToolCall(tc.connectorType, "t", tc.status, tc.class, time.Millisecond)
			if got := value(t, reg, "supermcp_tool_calls_total", map[string]string{
				"connector_type": tc.wantType, "status": tc.wantStatus, "error_class": tc.wantClass,
			}); got != 1 {
				t.Errorf("no series for {%s,%s,%s}", tc.wantType, tc.wantStatus, tc.wantClass)
			}
		})
	}
}

func TestObserveUpstreamIgnoresAZeroDuration(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	m := telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg})
	m.ObserveUpstream("http", 0)
	if n := seriesCount(t, reg, "supermcp_upstream_duration_seconds"); n != 0 {
		t.Errorf("upstream series = %d, want 0 when no upstream time was measured", n)
	}
}

func TestHandlerServesTheExpositionFormat(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	m := telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg})
	m.ObserveHTTPRequest("/healthz", http.MethodGet, http.StatusOK)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `supermcp_http_requests_total{code="200",method="GET",route="/healthz"} 1`) {
		t.Errorf("exposition did not carry the request counter:\n%s", rec.Body.String())
	}
}

// TestNilMetricsRecordsNothing keeps the call sites free of nil checks: a
// build without metrics passes nil and every instrument is a no-op.
func TestNilMetricsRecordsNothing(t *testing.T) {
	t.Parallel()
	var m *telemetry.Metrics
	m.ObserveToolCall("http", "t", telemetry.StatusSuccess, telemetry.ClassNone, time.Second)
	m.ObserveUpstream("http", time.Second)
	m.ObserveMCPRequest("tools/call", http.MethodPost, http.StatusOK)
	m.ObserveHTTPRequest("/x", http.MethodGet, http.StatusOK)
	m.ObserveSurfaceBuild(time.Second)
	m.SetBreakerState("c", telemetry.BreakerOpen)
	m.SetAuditQueueDepth(1)
	m.SetAuditDroppedTotal(1)
	m.SetRateLimitDegraded(true)
	m.ObserveKEK(telemetry.KEKProviderAWSKMS, telemetry.KEKUnwrap, errors.New("down"))
	m.SetAuditExportLag(map[string]time.Duration{telemetry.ExportKindWebhook: time.Hour})
	m.WatchDBPool(telemetry.PoolApp, func() telemetry.DBPoolStats { return telemetry.DBPoolStats{} })
	if m.Registry() != nil {
		t.Error("Registry on a nil Metrics returned a registry")
	}

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 from a nil Metrics handler", rec.Code)
	}
}

func family(t *testing.T, reg *prometheus.Registry, name string) *dto.MetricFamily {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return f
		}
	}
	return nil
}

func labelNames(t *testing.T, reg *prometheus.Registry, name string) []string {
	t.Helper()
	f := family(t, reg, name)
	if f == nil {
		t.Fatalf("no metric named %s", name)
	}
	if len(f.GetMetric()) == 0 {
		t.Fatalf("%s has no series", name)
	}
	out := []string{}
	for _, l := range f.GetMetric()[0].GetLabel() {
		out = append(out, l.GetName())
	}
	slices.Sort(out)
	return out
}

func seriesCount(t *testing.T, reg *prometheus.Registry, name string) int {
	t.Helper()
	n, err := testutil.GatherAndCount(reg, name)
	if err != nil {
		t.Fatalf("gather %s: %v", name, err)
	}
	return n
}

// value returns the single sample matching labels, failing when there is
// none: an assertion on a series that does not exist must not read as a
// zero.
func value(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	f := family(t, reg, name)
	if f == nil {
		t.Fatalf("no metric named %s", name)
	}
	for _, m := range f.GetMetric() {
		if !matches(m, labels) {
			continue
		}
		switch {
		case m.GetCounter() != nil:
			return m.GetCounter().GetValue()
		case m.GetGauge() != nil:
			return m.GetGauge().GetValue()
		default:
			t.Fatalf("%s is neither a counter nor a gauge", name)
		}
	}
	t.Fatalf("no series of %s with labels %v", name, labels)
	return 0
}

func matches(m *dto.Metric, labels map[string]string) bool {
	if len(m.GetLabel()) != len(labels) {
		return false
	}
	for _, l := range m.GetLabel() {
		if want, ok := labels[l.GetName()]; !ok || want != l.GetValue() {
			return false
		}
	}
	return true
}

// TestCacheInvalidationLabelsAreClosed keeps an organisation id, or any
// other caller-supplied string, out of the invalidation counter's labels.
func TestCacheInvalidationLabelsAreClosed(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	m := telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg})
	m.ObserveCacheInvalidation("org_0194f", "someone")
	m.ObserveCacheInvalidation(telemetry.CacheDLP, telemetry.InvalidationReconnect)

	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, f := range families {
		if f.GetName() != "supermcp_cache_invalidations_total" {
			continue
		}
		for _, s := range f.GetMetric() {
			key := ""
			for _, l := range s.GetLabel() {
				key += l.GetName() + "=" + l.GetValue() + ","
			}
			got[key] = s.GetCounter().GetValue()
		}
	}
	want := map[string]float64{
		"cache=other,source=other,":   1,
		"cache=dlp,source=reconnect,": 1,
	}
	if len(got) != len(want) {
		t.Fatalf("series = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}
