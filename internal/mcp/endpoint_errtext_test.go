package mcp

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/mcpserver"
	"github.com/supermcpco/supermcp/internal/reqid"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// TestSurfaceFailureAnswersTheRequestID calls the endpoint while the
// server lookup cannot reach the database. Any authenticated caller can
// get this far, from any workspace, so the JSON-RPC error must carry the
// generic message and the request id, not the driver's text (host, port,
// user, database), and the log must carry that text once under the id.
func TestSurfaceFailureAnswersTheRequestID(t *testing.T) {
	t.Parallel()
	// Nothing listens on port 1, so the lookup fails to connect.
	pool, err := pgxpool.New(context.Background(), "postgres://mcp_leak_user@127.0.0.1:1/mcp_leak_db?connect_timeout=2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var logs bytes.Buffer
	e := New(Deps{Servers: mcpserver.New(&tenant.DB{App: pool, Maint: pool}, nil, nil), Log: slog.New(slog.NewJSONHandler(&logs, nil))})
	r := chi.NewRouter()
	e.Routes(r)

	const id = "req-mcp-1"
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey, id)
	ctx = authz.WithPrincipal(ctx, &authz.Principal{Kind: authz.KindAPIKey, ID: "k_other_org", OrgID: "o_other"})
	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp/srv_1", body).WithContext(ctx))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), reqid.Message(id)) {
		t.Errorf("body %s does not carry %q", rec.Body.String(), reqid.Message(id))
	}
	for _, leak := range []string{"127.0.0.1", "mcp_leak_user", "mcp_leak_db", "dial", "SELECT"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("body %s leaks %q", rec.Body.String(), leak)
		}
	}
	if n := strings.Count(logs.String(), `"req_id":"`+id+`"`); n != 1 || !strings.Contains(logs.String(), "127.0.0.1") {
		t.Errorf("want the cause logged once under %s, got %d lines:\n%s", id, n, logs.String())
	}
}
