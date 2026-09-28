package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/supermcpco/supermcp/internal/config"
	"github.com/supermcpco/supermcp/internal/telemetry"
)

// recordingHandler keeps every record logged through it.
type recordingHandler struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = append(h.recs, r.Clone())
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) records() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]slog.Record(nil), h.recs...)
}

// attr is the value of the record's attribute key, or nil.
func attr(r slog.Record, key string) any {
	var v any
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			v = a.Value.Any()
			return false
		}
		return true
	})
	return v
}

// cancelKey carries the request's cancel func to the handler, which
// plays the caller going away by calling it.
type cancelKey struct{}

// httpCodes is how many requests the metrics counted under each status.
func httpCodes(t *testing.T, reg *prometheus.Registry) map[string]float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]float64{}
	for _, f := range families {
		if f.GetName() != telemetry.Namespace+"_http_requests_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "code" {
					codes[l.GetValue()] += m.GetCounter().GetValue()
				}
			}
		}
	}
	return codes
}

// clientGoneServer is the real router with one test operation that
// returns what fail makes of the request's context, a log that keeps its
// records, and the registry its metrics count in.
func clientGoneServer(t *testing.T, fail func(ctx context.Context) error) (http.Handler, *recordingHandler, *prometheus.Registry) {
	t.Helper()
	logs := &recordingHandler{}
	reg := prometheus.NewRegistry()
	h, api := New(Deps{
		Log:     slog.New(logs),
		Metrics: telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg}),
		Config:  &config.Config{PublicURL: &url.URL{Scheme: "https", Host: "supermcp.test"}},
	})
	huma.Register(api, huma.Operation{OperationID: "test-fail", Method: http.MethodGet, Path: "/test/fail"},
		func(ctx context.Context, _ *struct{}) (*struct{}, error) { return nil, fail(ctx) })
	return h, logs, reg
}

// TestClientGoneIsNotAServerError cancels the request's context in the
// middle of the handler, as net/http does when the browser navigates
// away, and has the handler fail the ways a cancelled query does. None
// of them is a server error: the answer is 499, the log has it at INFO
// with client_gone=true and nothing at WARN or above, the access log
// agrees on the status, and the request metrics count no 5xx.
func TestClientGoneIsNotAServerError(t *testing.T) {
	t.Parallel()
	goAway := func(ctx context.Context) {
		ctx.Value(cancelKey{}).(context.CancelFunc)()
		<-ctx.Done()
	}
	tests := []struct {
		name string
		fail func(ctx context.Context) error
	}{
		{"the driver reports the cancellation", func(ctx context.Context) error {
			goAway(ctx)
			return fmt.Errorf("statement timeout: %w", ctx.Err())
		}},
		{"Postgres stopped the statement with 57014", func(ctx context.Context) error {
			goAway(ctx)
			return toolCallsErr(ctx, fmt.Errorf("list tool calls: %w", &pgconn.PgError{Code: pgQueryCanceled}))
		}},
		{"a timeout mapping made a 503 of it", func(ctx context.Context) error {
			goAway(ctx)
			return errAuditTimeout
		}},
		{"a closed connection that does not wrap context.Canceled", func(ctx context.Context) error {
			goAway(ctx)
			return errors.New("conn closed")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h, logs, reg := clientGoneServer(t, tt.fail)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			ctx = context.WithValue(ctx, cancelKey{}, cancel)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test/fail", nil).WithContext(ctx))

			if rec.Code != statusClientClosedRequest {
				t.Errorf("status %d, want %d: %s", rec.Code, statusClientClosedRequest, rec.Body.String())
			}
			var gone, access int
			for _, r := range logs.records() {
				if r.Level >= slog.LevelWarn {
					t.Errorf("logged at %s: %s %v", r.Level, r.Message, r)
				}
				if r.Message == "request abandoned by the client" {
					gone++
					if r.Level != slog.LevelInfo || attr(r, "client_gone") != true {
						t.Errorf("level %s, client_gone %v; want INFO and true", r.Level, attr(r, "client_gone"))
					}
				}
				if r.Message == "http" {
					access++
					if got := attr(r, "status"); got != int64(statusClientClosedRequest) {
						t.Errorf("the access log has status %v, want %d", got, statusClientClosedRequest)
					}
				}
			}
			if gone != 1 || access != 1 {
				t.Errorf("%d client-gone records and %d access records, want one of each", gone, access)
			}
			codes := httpCodes(t, reg)
			for code, n := range codes {
				if code[0] == '5' {
					t.Errorf("%v requests counted under %s", n, code)
				}
			}
			if codes["499"] != 1 {
				t.Errorf("counted %v, want one 499", codes)
			}
		})
	}
}

// TestOwnDeadlineIsStillAServerError: a deadline of ours, with the caller
// still there, answers as before: the tool-call query's limit is a 503,
// and an unmapped one a 500 logged at ERROR, both counted as 5xx and
// neither taken for the caller going away.
func TestOwnDeadlineIsStillAServerError(t *testing.T) {
	t.Parallel()
	expired := func(ctx context.Context) error {
		qctx, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
		defer cancel()
		<-qctx.Done()
		return fmt.Errorf("list tool calls: %w", qctx.Err())
	}
	tests := []struct {
		name       string
		fail       func(ctx context.Context) error
		wantStatus int
		wantError  string // the message logged at ERROR, if any
	}{
		{"the query's own limit", func(ctx context.Context) error { return toolCallsErr(ctx, expired(ctx)) },
			http.StatusServiceUnavailable, ""},
		{"an unmapped deadline", expired, http.StatusInternalServerError, "request failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h, logs, reg := clientGoneServer(t, tt.fail)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test/fail", nil))

			if rec.Code != tt.wantStatus {
				t.Errorf("status %d, want %d: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			var errorLogged bool
			for _, r := range logs.records() {
				if attr(r, "client_gone") != nil {
					t.Errorf("taken for the caller going away: %s %v", r.Message, r)
				}
				if r.Level == slog.LevelError && r.Message == tt.wantError {
					errorLogged = true
				}
			}
			if tt.wantError != "" && !errorLogged {
				t.Errorf("no %q at ERROR", tt.wantError)
			}
			if got := httpCodes(t, reg)[fmt.Sprint(tt.wantStatus)]; got != 1 {
				t.Errorf("counted %v requests under %d, want 1", got, tt.wantStatus)
			}
		})
	}
}

func TestClientGone(t *testing.T) {
	t.Parallel()
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	late, cancelLate := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelLate()
	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"cancelled, with an error", gone, errors.New("conn closed"), true},
		{"cancelled, no error", gone, nil, false},
		{"our deadline on the request", late, context.DeadlineExceeded, false},
		{"still there", context.Background(), context.Canceled, false},
	}
	for _, tt := range tests {
		if got := clientGone(tt.ctx, tt.err); got != tt.want {
			t.Errorf("%s: clientGone = %v, want %v", tt.name, got, tt.want)
		}
	}
}
