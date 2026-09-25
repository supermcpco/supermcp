package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/config"
	"github.com/supermcpco/supermcp/internal/identity/sso"
	"github.com/supermcpco/supermcp/internal/scim"
)

// leakyHost and leakySQL are in the errors the handlers below return, so
// a test can tell whether they reached the client or the log.
const (
	leakyHost = "db-primary.internal.example"
	leakySQL  = "SELECT secret FROM connector_credentials"
)

// pgFailure is the kind of error a store method hands up: a driver error
// wrapped with the statement it came from and the server it went to.
func pgFailure() error {
	pg := &pgconn.PgError{Severity: "ERROR", Code: "42501", Message: "permission denied for table connector_credentials"}
	return fmt.Errorf("query %q on %s:5432: %w", leakySQL, leakyHost, pg)
}

// lockedBuffer is a log destination the handler and the test can share.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestUnmappedErrorsAnswerTheRequestID sends requests through the real
// router to handlers that fail in each way a handler can: returning a
// wrapped pgx error as it is, through humaErr, and with an error humaErr
// maps. An unmapped error must answer 500 with the generic message and
// the request id, which is also in X-Request-Id, and leave the SQL and the
// host to the log, where they appear once with the same id. A mapped
// error keeps its status and message.
func TestUnmappedErrorsAnswerTheRequestID(t *testing.T) {
	t.Parallel()
	var logs lockedBuffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	h, api := New(Deps{Log: log, Config: &config.Config{PublicURL: &url.URL{Scheme: "https", Host: "supermcp.test"}}})

	register := func(path string, err error) {
		huma.Register(api, huma.Operation{OperationID: "test-" + strings.TrimPrefix(path, "/test/"), Method: http.MethodGet, Path: path},
			func(context.Context, *struct{}) (*struct{}, error) { return nil, err })
	}
	register("/test/raw", pgFailure())
	register("/test/mapped-fallback", humaErr(pgFailure()))
	register("/test/not-found", humaErr(fmt.Errorf("load provider: %w", sso.ErrNotFound)))
	register("/test/denied", humaErr(fmt.Errorf("%w: connectors:create (no binding)", authz.ErrDenied)))

	tests := []struct {
		path       string
		wantStatus int
		wantDetail string // "" means the generic message with the request id
	}{
		{path: "/test/raw", wantStatus: http.StatusInternalServerError},
		{path: "/test/mapped-fallback", wantStatus: http.StatusInternalServerError},
		{path: "/test/not-found", wantStatus: http.StatusNotFound, wantDetail: "load provider: " + sso.ErrNotFound.Error()},
		{path: "/test/denied", wantStatus: http.StatusForbidden, wantDetail: "permission denied: connectors:create (no binding)"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.Header.Set(requestIDHeader, "chosen-by-the-client")
			h.ServeHTTP(rec, req)

			id := rec.Header().Get(requestIDHeader)
			if id == "" || id == "chosen-by-the-client" {
				t.Fatalf("X-Request-Id is %q, want an id the server chose", id)
			}
			if rec.Code != tt.wantStatus {
				t.Fatalf("status %d, want %d: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			var problem huma.ErrorModel
			if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
				t.Fatalf("body %q: %v", rec.Body.String(), err)
			}
			want := tt.wantDetail
			if want == "" {
				want = internalMessage(id)
				if len(problem.Errors) != 0 {
					t.Errorf("a 500 carries error details: %s", rec.Body.String())
				}
			}
			if problem.Detail != want {
				t.Errorf("detail %q, want %q", problem.Detail, want)
			}
			for _, leak := range []string{leakyHost, leakySQL, "connector_credentials", "42501"} {
				if strings.Contains(rec.Body.String(), leak) {
					t.Errorf("body %s leaks %q", rec.Body.String(), leak)
				}
			}
			if tt.wantDetail != "" {
				return
			}
			var causes int
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.Contains(line, `"req_id":"`+id+`"`) && strings.Contains(line, leakySQL) {
					causes++
					if !strings.Contains(line, leakyHost) {
						t.Errorf("the logged cause lacks the host: %s", line)
					}
				}
			}
			if causes != 1 {
				t.Errorf("the cause is logged %d times under request id %s, want once:\n%s", causes, id, logs.String())
			}
		})
	}
}

// TestRequestIDsDiffer checks every request gets an id of its own in
// X-Request-Id, on the routes huma does not serve as well: SCIM, which
// answers its own errors, and the health checks.
func TestRequestIDsDiffer(t *testing.T) {
	t.Parallel()
	h, _ := New(Deps{
		Log:    slog.New(slog.DiscardHandler),
		Config: &config.Config{PublicURL: &url.URL{Scheme: "https", Host: "supermcp.test"}},
		SCIM:   scim.New(nil, nil, nil, nil),
	})
	seen := map[string]bool{}
	for _, path := range []string{"/healthz", "/scim/v2/Users", "/scim/v2/Users", "/api/v1/org/members"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		id := rec.Header().Get(requestIDHeader)
		if id == "" || seen[id] {
			t.Fatalf("GET %s: request id %q is empty or repeated (seen %v)", path, id, seen)
		}
		seen[id] = true
	}
}
