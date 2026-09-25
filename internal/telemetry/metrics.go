package telemetry

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Namespace prefixes every series this process publishes.
const Namespace = "supermcp"

// OtherTool is the label value that per-tool series collapse into once the
// cap is reached.
const OtherTool = "_other"

// CallStatus is the outcome of a tool call, mirroring what the invocation
// row records.
type CallStatus string

const (
	StatusSuccess CallStatus = "success"
	StatusError   CallStatus = "error"
	StatusTimeout CallStatus = "timeout"
)

// ErrorClass groups failures into a fixed set. It is a closed set on
// purpose: an error class taken from an upstream message would put an
// unbounded number of series behind one metric name.
type ErrorClass string

const (
	ClassNone        ErrorClass = "none"
	ClassUpstream4xx ErrorClass = "upstream_4xx"
	ClassUpstream5xx ErrorClass = "upstream_5xx"
	ClassTimeout     ErrorClass = "timeout"
	ClassAuth        ErrorClass = "auth"
	ClassTransform   ErrorClass = "transform"
	ClassUnsupported ErrorClass = "unsupported"
	ClassConfig      ErrorClass = "config"
	// ClassPolicy is the instance's own refusal: a data-loss rule, or any
	// other governance decision that stopped a call the upstream would
	// have answered.
	ClassPolicy   ErrorClass = "policy"
	ClassInternal ErrorClass = "internal"
	// ClassOther catches anything a caller passes that is not in this set.
	ClassOther ErrorClass = "other"
)

// BreakerState is a circuit breaker's state as a number, because a gauge
// holds numbers and a state label would need one series per state.
type BreakerState float64

const (
	BreakerClosed   BreakerState = 0
	BreakerHalfOpen BreakerState = 1
	BreakerOpen     BreakerState = 2
)

// Master key operations, the providers that perform them, and the role
// of the key that did. All three are closed sets, like ErrorClass:
// anything else is recorded as OtherLabel, so
// supermcp_kek_operations_total never has more than 54 series.
const (
	KEKWrap   = "wrap"
	KEKUnwrap = "unwrap"

	KEKProviderLocal  = "local"
	KEKProviderAWSKMS = "awskms"

	// KEKKeyActive is the key that seals; KEKKeyPrevious one named in
	// SUPERMCP_KEK_PREVIOUS, which only opens.
	KEKKeyActive   = "active"
	KEKKeyPrevious = "previous"
)

// Audit export destination kinds, mirroring the audit package's own. A
// destination belongs to an organisation, so its id would be a label with
// no ceiling; the kind is the finest grain the lag is published at.
const (
	ExportKindWebhook = "webhook"
	ExportKindSyslog  = "syslog"
	ExportKindSplunk  = "splunk"
	ExportKindOTLP    = "otlp"
)

// OtherLabel is what a label value outside a closed set collapses into.
const OtherLabel = "other"

// MetricsOptions configure a Metrics.
type MetricsOptions struct {
	// Registry receives the instruments. Nil builds a private one, which
	// keeps the process free of a global default registry.
	Registry *prometheus.Registry
	// PerTool turns on the per-tool series. It is off by default: a tool
	// name is operator data, one organisation can install hundreds and the
	// label would grow the series count without a ceiling.
	PerTool bool
	// PerToolCap is how many distinct tool names get their own series
	// before the rest collapse into OtherTool. Defaults to 5000.
	PerToolCap int
	// GoCollectors adds the runtime and process collectors.
	GoCollectors bool
}

// Metrics is the process's instruments and the registry behind them. The
// rest of the code calls the typed methods here rather than touching
// prometheus directly, so the day this becomes OpenTelemetry is the day
// one file changes.
//
// A nil *Metrics is usable and records nothing, which is what a test or a
// cut-down build gets.
type Metrics struct {
	registry *prometheus.Registry

	toolCalls        *prometheus.CounterVec
	toolCallDuration *prometheus.HistogramVec
	toolCallsByTool  *prometheus.CounterVec
	upstreamDuration *prometheus.HistogramVec
	mcpRequests      *prometheus.CounterVec
	httpRequests     *prometheus.CounterVec
	surfaceBuild     prometheus.Histogram
	breakerState     *prometheus.GaugeVec
	auditQueueDepth  prometheus.Gauge
	auditSpoolDepth  prometheus.Gauge
	auditDropped     prometheus.Counter
	rateLimitDegrade prometheus.Gauge
	kekOperations    *prometheus.CounterVec
	auditExportLag   *prometheus.GaugeVec
	dbPools          *dbPoolCollector
	cacheInvalidate  *prometheus.CounterVec
	cacheListener    prometheus.Gauge
	mcpSessions      prometheus.Gauge
	mcpSessionsEnded *prometheus.CounterVec

	perTool    bool
	perToolCap int
	// droppedMu guards droppedSeen, the writer's total at the last
	// sample, so the counter moves by the difference.
	droppedMu   sync.Mutex
	droppedSeen int64
	// mu guards toolNames, the set of tool labels already admitted. It is
	// taken only when per-tool series are on.
	mu        sync.Mutex
	toolNames map[string]struct{}
}

// NewMetrics builds the instruments and registers them. It panics on a
// duplicate registration, which can only be a programming error: build one
// Metrics per registry.
func NewMetrics(opts MetricsOptions) *Metrics {
	if opts.Registry == nil {
		opts.Registry = prometheus.NewRegistry()
	}
	if opts.PerToolCap <= 0 {
		opts.PerToolCap = 5000
	}
	m := &Metrics{
		registry:   opts.Registry,
		perTool:    opts.PerTool,
		perToolCap: opts.PerToolCap,
		toolNames:  make(map[string]struct{}),

		toolCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "tool_calls_total",
			Help:      "Tool calls by connector transport, outcome and error class.",
		}, []string{"connector_type", "status", "error_class"}),

		toolCallDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "tool_call_duration_seconds",
			Help:      "End-to-end tool call latency, including auth, transform and recording.",
			Buckets:   prometheus.ExponentialBuckets(0.005, 2, 13),
		}, []string{"connector_type"}),

		toolCallsByTool: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "tool_calls_by_tool_total",
			Help:      "Tool calls by tool name, capped and collapsed into " + OtherTool + " past the cap.",
		}, []string{"tool", "connector_type", "status"}),

		upstreamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "upstream_duration_seconds",
			Help:      "Time spent waiting on the upstream system alone.",
			Buckets:   prometheus.ExponentialBuckets(0.005, 2, 13),
		}, []string{"connector_type"}),

		mcpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "mcp_requests_total",
			Help:      "MCP JSON-RPC requests by method and HTTP status.",
		}, []string{"endpoint", "method", "code"}),

		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "http_requests_total",
			Help:      "HTTP requests by routing pattern, method and status.",
		}, []string{"route", "method", "code"}),

		surfaceBuild: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "surface_build_seconds",
			Help:      "Time to compute one caller's visible tool surface.",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 12),
		}),

		breakerState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "breaker_state",
			Help:      "Circuit breaker state per connector: 0 closed, 1 half-open, 2 open.",
		}, []string{"connector"}),

		auditQueueDepth: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "audit_queue_depth",
			Help:      "Audit events waiting to be written.",
		}),

		auditSpoolDepth: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "audit_spool_depth",
			Help:      "Audit events waiting on disk for a database that would not take them.",
		}),

		auditDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "audit_events_dropped_total",
			Help:      "Audit events this replica accepted and could not write: the queue was full, the database refused them past the retries, or the spool would not take them. Each is also recorded in the stream as a gap.",
		}),

		rateLimitDegrade: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "ratelimit_degraded",
			Help:      "1 when rate limit budgets are per replica rather than shared through Redis.",
		}),

		kekOperations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "kek_operations_total",
			Help:      "Master key wraps and unwraps by provider, key role (active or previous) and outcome. Unwrapped data keys are cached, so this counts cache misses, not decryptions.",
		}, []string{"provider", "key", "op", "outcome"}),

		auditExportLag: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "audit_export_lag_seconds",
			Help:      "Age of the oldest audit event an enabled destination has not yet accepted, the worst across destinations of each kind. 0 when all are caught up.",
		}, []string{"kind"}),

		dbPools: newDBPoolCollector(),

		cacheInvalidate: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "cache_invalidations_total",
			Help:      "Cache invalidations by cache and by what caused them: a write on this replica (local), a database notification (notify), or the notification listener reconnecting (reconnect).",
		}, []string{"cache", "source"}),

		cacheListener: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "cache_listener_connected",
			Help:      "1 when this replica's cache invalidation listener is connected and delivering; 0 means changes on other replicas reach this one only when its cache entries expire.",
		}),

		mcpSessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "mcp_sessions",
			Help:      "MCP sessions this replica holds for servers set to stateful. Sessions are not shared between replicas.",
		}),

		mcpSessionsEnded: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "mcp_sessions_closed_total",
			Help:      "MCP sessions this replica closed, by why: idle past the limit, capacity to make room for a new one, client when the client ended it, shutdown when the replica drained, gone when the session had already ended, expired when it outlived the maximum age.",
		}, []string{"reason"}),
	}

	opts.Registry.MustRegister(
		m.toolCalls,
		m.toolCallDuration,
		m.toolCallsByTool,
		m.upstreamDuration,
		m.mcpRequests,
		m.httpRequests,
		m.surfaceBuild,
		m.breakerState,
		m.auditQueueDepth,
		m.auditSpoolDepth,
		m.auditDropped,
		m.rateLimitDegrade,
		m.kekOperations,
		m.auditExportLag,
		m.dbPools,
		m.cacheInvalidate,
		m.cacheListener,
		m.mcpSessions,
		m.mcpSessionsEnded,
	)
	if opts.GoCollectors {
		opts.Registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}
	return m
}

// Handler serves the exposition format. Mount it on the admin listener:
// /metrics on the public listener would publish the shape of the estate to
// anyone who asks.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		ErrorHandling:     promhttp.HTTPErrorOnError,
		EnableOpenMetrics: true,
	})
}

// Registry exposes the registry so a subsystem with its own collector can
// register it. Prefer a typed method here.
func (m *Metrics) Registry() *prometheus.Registry {
	if m == nil {
		return nil
	}
	return m.registry
}

// ObserveToolCall records one finished tool call. Pass an empty tool name
// when the call never resolved to one.
func (m *Metrics) ObserveToolCall(connectorType, tool string, status CallStatus, class ErrorClass, d time.Duration) {
	if m == nil {
		return
	}
	ct := labelOrUnknown(connectorType)
	st := normaliseStatus(status)
	m.toolCalls.WithLabelValues(ct, st, string(normaliseClass(class))).Inc()
	m.toolCallDuration.WithLabelValues(ct).Observe(d.Seconds())
	if m.perTool {
		m.toolCallsByTool.WithLabelValues(m.toolLabel(tool), ct, st).Inc()
	}
}

// ObserveUpstream records the time a call spent on the upstream system,
// which is the part supermcp does not control and the part an operator
// blames it for.
func (m *Metrics) ObserveUpstream(connectorType string, d time.Duration) {
	if m == nil || d <= 0 {
		return
	}
	m.upstreamDuration.WithLabelValues(labelOrUnknown(connectorType)).Observe(d.Seconds())
}

// ObserveMCPRequest records one JSON-RPC request on the MCP endpoint.
func (m *Metrics) ObserveMCPRequest(endpoint, method string, code int) {
	if m == nil {
		return
	}
	m.mcpRequests.WithLabelValues(labelOrUnknown(endpoint), labelOrUnknown(method), strconv.Itoa(code)).Inc()
}

// ObserveHTTPRequest records one HTTP request. route must be the chi
// routing pattern, never the raw path: a path carries ids and would give
// every resource its own series.
func (m *Metrics) ObserveHTTPRequest(route, method string, code int) {
	if m == nil {
		return
	}
	m.httpRequests.WithLabelValues(labelOrUnknown(route), labelOrUnknown(method), strconv.Itoa(code)).Inc()
}

// ObserveSurfaceBuild records how long one caller's tool surface took to
// compute. It runs on every MCP request, so it is the first thing to look
// at when tools/list is slow.
func (m *Metrics) ObserveSurfaceBuild(d time.Duration) {
	if m == nil {
		return
	}
	m.surfaceBuild.Observe(d.Seconds())
}

// SetBreakerState records a connector's circuit breaker state.
func (m *Metrics) SetBreakerState(connector string, state BreakerState) {
	if m == nil {
		return
	}
	m.breakerState.WithLabelValues(labelOrUnknown(connector)).Set(float64(state))
}

// SetAuditQueueDepth records how many audit events are waiting. A depth
// that stays near the buffer size means events are about to be dropped.
func (m *Metrics) SetAuditQueueDepth(n int) {
	if m == nil {
		return
	}
	m.auditQueueDepth.Set(float64(n))
}

// SetAuditSpoolDepth records how many events are on disk waiting for a
// database that would not take them. Anything above zero means the trail
// is being kept somewhere a backup does not reach, so it matters until it
// is back to zero.
func (m *Metrics) SetAuditSpoolDepth(n int) {
	if m == nil {
		return
	}
	m.auditSpoolDepth.Set(float64(n))
}

// SetAuditDroppedTotal records the audit writer's running count of events
// it had to discard. The writer's number only goes up, so the counter
// moves by what has been added since the last sample.
func (m *Metrics) SetAuditDroppedTotal(total int64) {
	if m == nil {
		return
	}
	m.droppedMu.Lock()
	defer m.droppedMu.Unlock()
	if total > m.droppedSeen {
		m.auditDropped.Add(float64(total - m.droppedSeen))
		m.droppedSeen = total
	}
}

// SetRateLimitDegraded records whether rate limit budgets are shared.
func (m *Metrics) SetRateLimitDegraded(degraded bool) {
	if m == nil {
		return
	}
	var v float64
	if degraded {
		v = 1
	}
	m.rateLimitDegrade.Set(v)
}

// ObserveKEK records one master key operation. provider is the KEK's
// provider (local or awskms), key is KEKKeyActive or KEKKeyPrevious, op
// is KEKWrap or KEKUnwrap. A caller that gave up on the call should not
// report it: a cancelled request says nothing about whether the key
// service is reachable.
func (m *Metrics) ObserveKEK(provider, key, op string, err error) {
	if m == nil {
		return
	}
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	m.kekOperations.WithLabelValues(oneOf(provider, KEKProviderLocal, KEKProviderAWSKMS),
		oneOf(key, KEKKeyActive, KEKKeyPrevious), oneOf(op, KEKWrap, KEKUnwrap), outcome).Inc()
}

// SetAuditExportLag records, per destination kind, how long the oldest
// undelivered event has been waiting. Every kind is written on each call,
// zero where the map has nothing, so a kind whose last destination was
// switched off stops reporting its old lag. A kind this package does not
// know is folded into OtherLabel rather than given a series of its own.
func (m *Metrics) SetAuditExportLag(lag map[string]time.Duration) {
	if m == nil {
		return
	}
	kinds := [...]string{ExportKindWebhook, ExportKindSyslog, ExportKindSplunk, ExportKindOTLP}
	worst := make(map[string]time.Duration, len(kinds)+1)
	for kind, d := range lag {
		k := oneOf(kind, kinds[:]...)
		worst[k] = max(worst[k], d)
	}
	for _, kind := range append(kinds[:], OtherLabel) {
		m.auditExportLag.WithLabelValues(kind).Set(worst[kind].Seconds())
	}
}

// Caches and invalidation sources, closed sets like the others: anything
// else is recorded as OtherLabel.
const (
	CacheAuthz = "authz"
	CacheDLP   = "dlp"

	InvalidationLocal     = "local"
	InvalidationNotify    = "notify"
	InvalidationReconnect = "reconnect"
)

// ObserveCacheInvalidation counts one invalidation of cache, caused by
// source.
func (m *Metrics) ObserveCacheInvalidation(cache, source string) {
	if m == nil {
		return
	}
	m.cacheInvalidate.WithLabelValues(oneOf(cache, CacheAuthz, CacheDLP),
		oneOf(source, InvalidationLocal, InvalidationNotify, InvalidationReconnect)).Inc()
}

// SetCacheListenerConnected records whether the cache invalidation
// listener is connected.
func (m *Metrics) SetCacheListenerConnected(connected bool) {
	if m == nil {
		return
	}
	var v float64
	if connected {
		v = 1
	}
	m.cacheListener.Set(v)
}

// Why an MCP session ended, a closed set: anything else is recorded as
// OtherLabel.
const (
	SessionClosedIdle     = "idle"
	SessionClosedCapacity = "capacity"
	SessionClosedClient   = "client"
	SessionClosedShutdown = "shutdown"
	SessionClosedGone     = "gone"
	SessionClosedExpired  = "expired"
)

// SetMCPSessions records how many MCP sessions this replica holds.
func (m *Metrics) SetMCPSessions(n int) {
	if m == nil {
		return
	}
	m.mcpSessions.Set(float64(n))
}

// ObserveMCPSessionClosed counts one session ending, for reason.
func (m *Metrics) ObserveMCPSessionClosed(reason string) {
	if m == nil {
		return
	}
	m.mcpSessionsEnded.WithLabelValues(oneOf(reason, SessionClosedIdle, SessionClosedCapacity,
		SessionClosedClient, SessionClosedShutdown, SessionClosedGone, SessionClosedExpired)).Inc()
}

// toolLabel admits a tool name until the cap, then returns OtherTool.
//
// Tool names come from adapters an operator installs, so their number has
// no ceiling this process controls. Without the cap one busy tenant would
// multiply every per-tool series and take the scrape, and then Prometheus,
// down with it. Past the cap the counts are still correct in total; only
// the attribution is lost, which is the right thing to lose.
func (m *Metrics) toolLabel(name string) string {
	if name == "" {
		return OtherTool
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.toolNames[name]; ok {
		return name
	}
	if len(m.toolNames) >= m.perToolCap {
		return OtherTool
	}
	m.toolNames[name] = struct{}{}
	return name
}

func normaliseStatus(s CallStatus) string {
	switch s {
	case StatusSuccess, StatusError, StatusTimeout:
		return string(s)
	default:
		return string(StatusError)
	}
}

func normaliseClass(c ErrorClass) ErrorClass {
	switch c {
	case ClassNone, ClassUpstream4xx, ClassUpstream5xx, ClassTimeout, ClassAuth,
		ClassTransform, ClassUnsupported, ClassConfig, ClassInternal, ClassOther:
		return c
	default:
		return ClassOther
	}
}

// oneOf returns v if it is one of allowed and OtherLabel otherwise.
func oneOf(v string, allowed ...string) string {
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return OtherLabel
}

// labelOrUnknown keeps an empty label from producing a series that reads
// as a bug in the dashboard rather than in the caller.
func labelOrUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}
