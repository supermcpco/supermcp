package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/supermcpco/supermcp/internal/config"
	"github.com/supermcpco/supermcp/internal/secrets"
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
	return counted(t, reg, "http_requests_total", "code")
}

// counted sums the series of metric (without the namespace) by label.
func counted(t *testing.T, reg *prometheus.Registry, metric, label string) map[string]float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]float64{}
	for _, f := range families {
		if f.GetName() != telemetry.Namespace+"_"+metric {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == label {
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
func clientGoneServer(t *testing.T, fail func(ctx context.Context) error, mw ...func(huma.Context, func(huma.Context))) (http.Handler, *recordingHandler, *prometheus.Registry) {
	t.Helper()
	logs := &recordingHandler{}
	reg := prometheus.NewRegistry()
	h, api := New(Deps{
		Log:     slog.New(logs),
		Metrics: telemetry.NewMetrics(telemetry.MetricsOptions{Registry: reg}),
		Config:  &config.Config{PublicURL: &url.URL{Scheme: "https", Host: "supermcp.test"}},
	})
	huma.Register(api, huma.Operation{OperationID: "test-fail", Method: http.MethodGet, Path: "/test/fail", Middlewares: mw},
		func(ctx context.Context, _ *struct{}) (*struct{}, error) { return nil, fail(ctx) })
	return h, logs, reg
}

// goAway plays the browser navigating away: it cancels the request's
// context, as net/http does, and waits for it to end.
func goAway(ctx context.Context) {
	ctx.Value(cancelKey{}).(context.CancelFunc)()
	<-ctx.Done()
}

// serveGone sends one request to h and hangs up in the middle of it.
func serveGone(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx = context.WithValue(ctx, cancelKey{}, cancel)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test/fail", nil).WithContext(ctx))
	return rec
}

// checkGone asserts what a request abandoned mid-handler leaves: a 499,
// one client-gone record at level with orig_status and no status, no
// other record at WARN or above, an access log that agrees on 499, one
// 499 and no 5xx in the request metrics, and one client-gone count for
// the route and origStatus. It returns the client-gone record.
func checkGone(t *testing.T, rec *httptest.ResponseRecorder, logs *recordingHandler, reg *prometheus.Registry,
	level slog.Level, origStatus int) slog.Record {
	t.Helper()
	if rec.Code != statusClientClosedRequest {
		t.Errorf("status %d, want %d: %s", rec.Code, statusClientClosedRequest, rec.Body.String())
	}
	var goneRec slog.Record
	var gone, access int
	for _, r := range logs.records() {
		if r.Message == "request abandoned by the client" {
			gone++
			goneRec = r
			if r.Level != level || attr(r, "client_gone") != true {
				t.Errorf("level %s, client_gone %v; want %s and true", r.Level, attr(r, "client_gone"), level)
			}
			if got := attr(r, "orig_status"); got != int64(origStatus) {
				t.Errorf("orig_status %v, want %d", got, origStatus)
			}
			if got := attr(r, "status"); got != nil {
				t.Errorf("the client-gone line has status %v, which a search for server errors would match", got)
			}
			continue
		}
		if r.Level >= slog.LevelWarn {
			t.Errorf("logged at %s: %s %v", r.Level, r.Message, r)
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
	if got := counted(t, reg, "http_client_gone_total", "orig_status"); len(got) != 1 || got[fmt.Sprint(origStatus)] != 1 {
		t.Errorf("client-gone counted %v, want one under %d", got, origStatus)
	}
	if got := counted(t, reg, "http_client_gone_total", "route"); got["/test/fail"] != 1 {
		t.Errorf("client-gone counted by route %v, want one under the route pattern", got)
	}
	return goneRec
}

// TestClientGoneIsNotAServerError cancels the request's context in the
// middle of the handler, as net/http does when the browser navigates
// away, and has the handler fail the ways a cancelled request does. None
// of them is a server error: see checkGone. A cancelled query the
// handler mapped is logged at INFO; an unmapped 500, which could be a bug
// a caller hid by hanging up, at WARN.
func TestClientGoneIsNotAServerError(t *testing.T) {
	t.Parallel()
	kms := fmt.Errorf("decrypt with %s: %w", leakyARN, secrets.ErrKeyServiceUnavailable)
	tests := []struct {
		name      string
		fail      func(ctx context.Context) error
		level     slog.Level
		orig      int
		wantCause string // text the logged err must contain
	}{
		{"an unmapped cancellation", func(ctx context.Context) error {
			goAway(ctx)
			return fmt.Errorf("statement timeout: %w", ctx.Err())
		}, slog.LevelWarn, http.StatusInternalServerError, "statement timeout: context canceled"},
		{"Postgres stopped the tool-call statement with 57014", func(ctx context.Context) error {
			goAway(ctx)
			return toolCallsErr(ctx, fmt.Errorf("list tool calls: %w", &pgconn.PgError{Code: pgQueryCanceled}))
		}, slog.LevelInfo, http.StatusServiceUnavailable, "list tool calls"},
		{"a cancelled query mapped by goneErr", func(ctx context.Context) error {
			goAway(ctx)
			return goneErr(ctx, fmt.Errorf("usage series: %w", ctx.Err()))
		}, slog.LevelInfo, http.StatusServiceUnavailable, "usage series: context canceled"},
		{"a timeout mapping made a 503 of it", func(ctx context.Context) error {
			goAway(ctx)
			return errAuditTimeout
		}, slog.LevelInfo, http.StatusServiceUnavailable, ""},
		{"the key service's 503", func(ctx context.Context) error {
			goAway(ctx)
			return humaErr(kms)
		}, slog.LevelInfo, http.StatusServiceUnavailable, "decrypt with"},
		{"a closed connection that does not wrap context.Canceled", func(ctx context.Context) error {
			goAway(ctx)
			return errors.New("conn closed")
		}, slog.LevelWarn, http.StatusInternalServerError, "conn closed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h, logs, reg := clientGoneServer(t, tt.fail)
			r := checkGone(t, serveGone(t, h), logs, reg, tt.level, tt.orig)
			causes, _ := attr(r, "err").([]string)
			if tt.wantCause != "" && !strings.Contains(strings.Join(causes, "\n"), tt.wantCause) {
				t.Errorf("err %q, want it to contain %q", causes, tt.wantCause)
			}
		})
	}
}

// TestClientGoneBehindAWrappingMiddleware: an operation middleware that
// wraps the context, as huma.WithValue does, stands between the
// goneAwareContext and the transformer. The caller going away must still
// be answered 499, not the 5xx.
func TestClientGoneBehindAWrappingMiddleware(t *testing.T) {
	t.Parallel()
	type key struct{}
	wrap := func(ctx huma.Context, next func(huma.Context)) {
		next(huma.WithValue(ctx, key{}, "wrapped"))
	}
	h, logs, reg := clientGoneServer(t, func(ctx context.Context) error {
		if ctx.Value(key{}) != "wrapped" {
			t.Error("the middleware did not wrap the context")
		}
		goAway(ctx)
		return fmt.Errorf("statement timeout: %w", ctx.Err())
	}, wrap)
	checkGone(t, serveGone(t, h), logs, reg, slog.LevelWarn, http.StatusInternalServerError)
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
