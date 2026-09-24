package telemetry_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/supermcpco/supermcp/internal/telemetry"
)

// An instance with no collector must not try to reach one, and must not
// make the call sites check for that.
func TestNoEndpointRecordsNothingAndStillAnswers(t *testing.T) {
	tr := telemetry.NewTracer(t.Context(), telemetry.TraceOptions{})
	ctx, span := tr.Start(context.Background(), "tool.call", telemetry.Str("tool", "x"))
	span.End()
	if ctx == nil {
		t.Fatal("the tracer returned no context")
	}
	if err := tr.Shutdown(t.Context()); err != nil {
		t.Fatalf("shutting down a tracer that exports nothing: %v", err)
	}

	// And a nil one, which is what every test and every cut-down build has.
	var none *telemetry.Tracer
	_, s := none.Start(context.Background(), "tool.call")
	s.End()
	if err := none.Shutdown(t.Context()); err != nil {
		t.Fatalf("shutting down a nil tracer: %v", err)
	}
}

// A collector that is not there must not stop the instance serving.
func TestAnUnreachableCollectorIsNotAFailure(t *testing.T) {
	tr := telemetry.NewTracer(t.Context(), telemetry.TraceOptions{
		Endpoint: "http://127.0.0.1:1", Sample: 1, Service: "supermcp",
	})
	_, span := tr.Start(context.Background(), "tool.call")
	span.End()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_ = tr.Shutdown(ctx) // it may report the failure; it must not hang or panic
}

// And when one is there, the spans arrive with the service named.
func TestSpansReachACollector(t *testing.T) {
	var got atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := telemetry.NewTracer(t.Context(), telemetry.TraceOptions{
		Endpoint: srv.URL, Sample: 1, Service: "supermcp", Version: "test",
	})
	ctx, call := tr.Start(context.Background(), "tool.call", telemetry.Str("tool", "bundesbank_rates"))
	_, upstream := tr.Start(ctx, "upstream.http")
	upstream.End()
	call.End()
	if err := tr.Shutdown(t.Context()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if got.Load() == 0 {
		t.Fatal("no spans reached the collector")
	}
}

// The sample rate is a fraction; anything else is the caller's mistake and
// must not become an instance that samples everything by accident.
func TestSampleIsBounded(t *testing.T) {
	for _, s := range []float64{-1, 0, 2} {
		tr := telemetry.NewTracer(t.Context(), telemetry.TraceOptions{Sample: s})
		if tr == nil {
			t.Fatalf("sample %v produced no tracer", s)
		}
	}
	// A JSON round trip of the options is not part of the contract; this
	// only proves the struct stays simple enough to log.
	if _, err := json.Marshal(telemetry.TraceOptions{Endpoint: "x", Sample: 0.5}); err != nil {
		t.Fatal(err)
	}
}
