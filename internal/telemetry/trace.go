package telemetry

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Metrics say how often and how long; a trace says where inside one call
// the time went, which is the question an operator has when a tool call
// is slow and the upstream is not. Nothing is exported unless an endpoint
// is configured: an instance with no collector pays for a no-op tracer
// and no network at all.
//
// Trace context is deliberately not sent upstream. A connector points at
// somebody else's system, and a header we invent there is data leaving
// this instance to a vendor who did not ask for it.

// TraceOptions configure the exporter.
type TraceOptions struct {
	// Endpoint is an OTLP/HTTP collector, for example
	// "http://otel-collector:4318". Empty turns tracing off.
	Endpoint string
	// Insecure sends over http. A collector inside the cluster usually is.
	Insecure bool
	// Sample is the fraction of traces kept, 0 to 1. Zero means one in a
	// hundred, which is enough to see shape without paying for volume.
	Sample  float64
	Service string
	Version string
	Log     *slog.Logger
}

// Tracer is the endpoint's view of tracing: a span factory and a way to
// stop. A zero Tracer is usable and records nothing.
type Tracer struct {
	trace.Tracer
	shutdown func(context.Context) error
}

// Shutdown flushes what has not been sent. It is called on the way out,
// because a trace of the request that broke everything is exactly the one
// worth keeping.
func (t *Tracer) Shutdown(ctx context.Context) error {
	if t == nil || t.shutdown == nil {
		return nil
	}
	return t.shutdown(ctx)
}

// NewTracer builds one. It never fails the boot: an instance that cannot
// reach its collector should still serve requests, so a bad endpoint is a
// log line and a tracer that records nothing.
func NewTracer(ctx context.Context, o TraceOptions) *Tracer {
	if o.Endpoint == "" {
		return &Tracer{Tracer: noop.NewTracerProvider().Tracer("supermcp")}
	}
	endpoint := strings.TrimPrefix(strings.TrimPrefix(o.Endpoint, "http://"), "https://")
	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
	if o.Insecure || strings.HasPrefix(o.Endpoint, "http://") {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		if o.Log != nil {
			o.Log.Error("traces will not be exported", "endpoint", o.Endpoint, "err", err)
		}
		return &Tracer{Tracer: noop.NewTracerProvider().Tracer("supermcp")}
	}
	sample := o.Sample
	if sample <= 0 {
		sample = 0.01
	}
	if sample > 1 {
		sample = 1
	}
	host, _ := os.Hostname()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sample))),
		sdktrace.WithResource(resource.NewWithAttributes(semconv.SchemaURL,
			semconv.ServiceName(orDefault(o.Service, "supermcp")),
			semconv.ServiceVersion(o.Version),
			semconv.HostName(host),
		)),
	)
	// The global is set because the libraries that create spans of their
	// own read it; ours take the tracer explicitly.
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))
	return &Tracer{Tracer: tp.Tracer("supermcp"), shutdown: tp.Shutdown}
}

// Start opens a span. A nil Tracer still answers, so no call site needs a
// check around it.
func (t *Tracer) Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if t == nil || t.Tracer == nil {
		return ctx, noop.Span{}
	}
	return t.Tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// Str and Int are the attribute constructors the call sites need, so that
// no other package has to import OpenTelemetry to describe a span.
func Str(k, v string) attribute.KeyValue { return attribute.String(k, v) }

// Int64 records a count or a duration in the unit the name states.
func Int64(k string, v int64) attribute.KeyValue { return attribute.Int64(k, v) }

// Bool records a decision.
func Bool(k string, v bool) attribute.KeyValue { return attribute.Bool(k, v) }

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
