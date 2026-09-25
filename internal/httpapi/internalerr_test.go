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
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/config"
	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/identity/sso"
	"github.com/supermcpco/supermcp/internal/reqid"
	"github.com/supermcpco/supermcp/internal/scim"
	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

// leakyHost and leakySQL are in the errors the handlers below return, so
// a test can tell whether they reached the client or the log.
const (
	leakyHost = "db-primary.internal.example"
	leakySQL  = "SELECT secret FROM connector_credentials"
	leakyARN  = "arn:aws:kms:eu-west-1:123456789012:key/0f1e2d3c"
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
// wrapped pgx error as it is, through humaErr, with an error humaErr
// maps, through the dry run's and the organisation switch's own mapping,
// and by panicking. An unmapped error must answer 500 with the generic
// message and the request id, which is also in X-Request-Id, and leave the
// SQL and the host to the log, where they appear once with the same id. A
// mapped error keeps its status and message, and neither kind carries the
// key service's ARN.
func TestUnmappedErrorsAnswerTheRequestID(t *testing.T) {
	t.Parallel()
	var logs lockedBuffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	h, api := New(Deps{Log: log, Config: &config.Config{PublicURL: &url.URL{Scheme: "https", Host: "supermcp.test"}}})

	handle := func(path string, fn func() error) {
		huma.Register(api, huma.Operation{OperationID: "test-" + strings.TrimPrefix(path, "/test/"), Method: http.MethodGet, Path: path},
			func(context.Context, *struct{}) (*struct{}, error) { return nil, fn() })
	}
	register := func(path string, err error) { handle(path, func() error { return err }) }
	_, refusedSwitch := switchOrgAnswer(fmt.Errorf("switch: %w", identity.ErrNotInOrganization))
	_, failedSwitch := switchOrgAnswer(pgFailure())
	kms := fmt.Errorf("decrypt with %s: %w", leakyARN, secrets.ErrKeyServiceUnavailable)

	register("/test/raw", pgFailure())
	register("/test/mapped-fallback", humaErr(pgFailure()))
	register("/test/not-found", humaErr(fmt.Errorf("load provider: %w", sso.ErrNotFound)))
	register("/test/denied", humaErr(fmt.Errorf("%w: connectors:create (no binding)", authz.ErrDenied)))
	register("/test/dry-run-driver", dryRunErr(pgFailure()))
	register("/test/dry-run-key-service", dryRunErr(kms))
	register("/test/dry-run-unset", dryRunErr(fmt.Errorf("render url: %w: {{params.id}}", tmpl.ErrUnset)))
	register("/test/switch-org-driver", failedSwitch)
	register("/test/switch-org-refused", refusedSwitch)
	handle("/test/panic", func() error { panic(pgFailure().Error()) })

	tests := []struct {
		path       string
		wantStatus int
		wantDetail string // "" means the generic message with the request id
	}{
		{path: "/test/raw", wantStatus: http.StatusInternalServerError},
		{path: "/test/mapped-fallback", wantStatus: http.StatusInternalServerError},
		{path: "/test/not-found", wantStatus: http.StatusNotFound, wantDetail: "load provider: " + sso.ErrNotFound.Error()},
		{path: "/test/denied", wantStatus: http.StatusForbidden, wantDetail: "permission denied: connectors:create (no binding)"},
		{path: "/test/dry-run-driver", wantStatus: http.StatusInternalServerError},
		{path: "/test/dry-run-key-service", wantStatus: http.StatusServiceUnavailable, wantDetail: keyServiceMessage},
		{path: "/test/dry-run-unset", wantStatus: http.StatusUnprocessableEntity,
			wantDetail: "the request could not be rendered: render url: unset placeholder: {{params.id}}"},
		{path: "/test/switch-org-driver", wantStatus: http.StatusInternalServerError},
		{path: "/test/switch-org-refused", wantStatus: http.StatusForbidden, wantDetail: identity.ErrNotInOrganization.Error()},
		{path: "/test/panic", wantStatus: http.StatusInternalServerError},
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
				want = reqid.Message(id)
				if len(problem.Errors) != 0 {
					t.Errorf("a 500 carries error details: %s", rec.Body.String())
				}
			}
			if problem.Detail != want {
				t.Errorf("detail %q, want %q", problem.Detail, want)
			}
			for _, leak := range []string{leakyHost, leakySQL, "connector_credentials", "42501", leakyARN} {
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

// TestSwitchOrgBoundsTheID checks the organisation id is refused before
// the handler when it is too long or not an id, so neither the audit
// trail nor an error message can be handed arbitrary text through it.
func TestSwitchOrgBoundsTheID(t *testing.T) {
	t.Parallel()
	h, _ := New(Deps{Log: slog.New(slog.DiscardHandler), Config: &config.Config{PublicURL: &url.URL{Scheme: "https", Host: "supermcp.test"}}})
	for _, id := range []string{strings.Repeat("a", 65), "o_1 OR 1=1", ""} {
		rec := httptest.NewRecorder()
		body := strings.NewReader(`{"organizationId":` + strconv.Quote(id) + `}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/switch-org", body)
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("organizationId %q: status %d, want 422: %s", id, rec.Code, rec.Body.String())
		}
	}
}

// TestReadyzSaysNothingAboutTheDatabase points /readyz at a database that
// is not there. The endpoint is unauthenticated, so the body must not
// carry the driver's error (user, database, host); the log must, with the
// request id.
func TestReadyzSaysNothingAboutTheDatabase(t *testing.T) {
	t.Parallel()
	// Nothing listens on port 1, so the ping fails to connect.
	pool, err := pgxpool.New(context.Background(), "postgres://readyz_leak_user@127.0.0.1:1/readyz_leak_db?connect_timeout=2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var logs lockedBuffer
	h, _ := New(Deps{Log: slog.New(slog.NewJSONHandler(&logs, nil)), Store: &store.Store{App: pool, Maint: pool},
		Config: &config.Config{PublicURL: &url.URL{Scheme: "https", Host: "supermcp.test"}}})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable || strings.TrimSpace(rec.Body.String()) != "database unavailable" {
		t.Fatalf("status %d body %q, want 503 \"database unavailable\"", rec.Code, rec.Body.String())
	}
	for _, leak := range []string{"127.0.0.1", "readyz_leak_user", "readyz_leak_db", "dial"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("body %q leaks %q", rec.Body.String(), leak)
		}
	}
	id := rec.Header().Get(requestIDHeader)
	if id == "" || !strings.Contains(logs.String(), `"req_id":"`+id+`"`) || !strings.Contains(logs.String(), "readyz_leak_db") {
		t.Errorf("the log does not carry the cause under request id %q:\n%s", id, logs.String())
	}
}
