package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/reqid"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// TestUnmappedErrorAnswersTheRequestID lists users against a database
// that is not there. The driver's error names the host, the port, the
// user and the database; the provider must get a 500 with the generic
// message and the request id, and the log must get the driver's error
// with the same id, once.
func TestUnmappedErrorAnswersTheRequestID(t *testing.T) {
	t.Parallel()
	// Nothing listens on port 1, so the first query fails to connect.
	pool, err := pgxpool.New(context.Background(), "postgres://scim_leak_user@127.0.0.1:1/scim_leak_db?connect_timeout=2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var logs bytes.Buffer
	s := New(&tenant.DB{App: pool, Maint: pool}, nil, nil, func() string { return "id" })
	s.Log = slog.New(slog.NewJSONHandler(&logs, nil))

	r := chi.NewRouter()
	r.Get("/scim/v2/Users", s.listUsers)
	const id = "req-scim-1"
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey, id)
	ctx = authz.WithPrincipal(ctx, &authz.Principal{Kind: authz.KindAPIKey, ID: "k_scim", OrgID: "o_scim"})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil).WithContext(ctx))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Schemas []string `json:"schemas"`
		Status  string   `json:"status"`
		Detail  string   `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Detail != reqid.Message(id) || body.Status != "500" || len(body.Schemas) != 1 || body.Schemas[0] != schemaError {
		t.Errorf("body %s, want a SCIM error with detail %q", rec.Body.String(), reqid.Message(id))
	}
	for _, leak := range []string{"127.0.0.1", "scim_leak_user", "scim_leak_db", "SELECT", "dial"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("body %s leaks %q", rec.Body.String(), leak)
		}
	}
	var causes int
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, `"req_id":"`+id+`"`) && strings.Contains(line, "127.0.0.1") {
			causes++
		}
	}
	if causes != 1 {
		t.Errorf("the cause is logged %d times under request id %s, want once:\n%s", causes, id, logs.String())
	}
}
