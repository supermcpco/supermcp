package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/reqid"
	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// TestErrorMeta checks what the audit trail says about each kind of
// error: a stable code and the caller's message for one the API answers
// itself, the generic message for anything else, and the request id
// either way.
func TestErrorMeta(t *testing.T) {
	t.Parallel()
	const id = "req-meta-1"
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey, id)

	tests := []struct {
		name        string
		err         error
		wantCode    string
		wantMessage string // "" means no message is recorded
	}{
		{name: "a wrapped pgx error", err: pgFailure(), wantCode: reqid.Message(id)},
		{name: "a refusal", err: fmt.Errorf("%w: roles:create (no binding)", authz.ErrDenied),
			wantCode: "forbidden", wantMessage: "permission denied: roles:create (no binding)"},
		{name: "a refusal with a code of its own", err: fmt.Errorf("remove member: %w", identity.ErrLastOwner),
			wantCode: conflictLastOwner, wantMessage: "remove member: " + identity.ErrLastOwner.Error()},
		{name: "an answer built by the handler", err: huma.Error422UnprocessableEntity("retention must be between 30 and 400 days"),
			wantCode: "unprocessable_entity", wantMessage: "retention must be between 30 and 400 days"},
		{name: "a detail value that is not a code", err: huma.Error409Conflict("taken", &huma.ErrorDetail{Value: "Ada's Role"}),
			wantCode: "conflict", wantMessage: "taken"},
		{name: "an OAuth error", err: &mcpauth.OAuthError{Code: "invalid_redirect_uri", Description: "redirect_uris must be https", Status: 400},
			wantCode: "invalid_redirect_uri", wantMessage: "redirect_uris must be https"},
		{name: "the key service", err: fmt.Errorf("seal: %w", secrets.ErrKeyServiceUnavailable),
			wantCode: "service_unavailable", wantMessage: keyServiceMessage},
		{name: "a long message is cut", err: huma.Error400BadRequest(strings.Repeat("é", 300)),
			wantCode: "bad_request", wantMessage: strings.Repeat("é", maxAuditMessage) + "…"},
		{name: "a 500 built by hand", err: huma.Error500InternalServerError("dial tcp " + leakyHost),
			wantCode: reqid.Message(id)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			meta := errorMeta(ctx, map[string]any{"method": "password"}, "reason", tt.err)
			if meta["reason"] != tt.wantCode {
				t.Errorf("reason %q, want %q", meta["reason"], tt.wantCode)
			}
			if got, _ := meta["message"].(string); got != tt.wantMessage {
				t.Errorf("message %q, want %q", got, tt.wantMessage)
			}
			if meta["requestId"] != id || meta["method"] != "password" {
				t.Errorf("meta %v lost the request id or the caller's keys", meta)
			}
			b, _ := json.Marshal(meta)
			for _, leak := range []string{leakyHost, leakySQL} {
				if strings.Contains(string(b), leak) {
					t.Errorf("meta %s leaks %q", b, leak)
				}
			}
		})
	}
}

// TestAdminFailedRecordsNoErrorText writes the audit event for an admin
// change that failed with a wrapped pgx error, and reads it back from
// the database: meta.error is the generic message, meta.requestId and
// the event's request_id are the request's, and neither the SQL nor the
// host is anywhere in the row. It also writes a refused import, whose
// message quotes the uploaded document: only the code is kept. Requires
// DATABASE_URL.
func TestAdminFailedRecordsNoErrorText(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	maint, err := store.Open(ctx, dsn, dsn, log, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := maint.Migrate(ctx, true); err != nil {
		maint.Close()
		t.Fatal(err)
	}
	maint.Close()
	st, err := store.Open(ctx, dsn, dsn, log, store.Options{AppRole: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}

	const org = "errtext_admin_failed"
	purge := func() {
		// audit_events has no foreign key to the workspace; the rows are
		// removed by id.
		if err := db.Bypass(context.WithoutCancel(ctx), "errtext cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM audit_events WHERE organization_id = $1`, org)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	purge()
	t.Cleanup(purge)

	w := audit.NewWriter(db, log, audit.Options{}) //nolint:contextcheck // the writer appends from its own goroutine
	t.Cleanup(w.Close)

	const id = "req-admin-failed-1"
	rctx := context.WithValue(ctx, middleware.RequestIDKey, id)
	rctx = authz.WithPrincipal(rctx, &authz.Principal{Kind: authz.KindUser, ID: "u_errtext", OrgID: org, AuthMethod: "session"})
	Deps{Audit: w}.adminFailed(rctx, "role.create", "role", "", pgFailure())
	Deps{Audit: w}.adminFailed(rctx, "connector.import", "connector", "doc",
		huma.Error400BadRequest("the document cannot be imported: line 3: "+leakySQL))
	if err := w.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	var (
		raw   []byte
		reqID *string
	)
	if err := db.Bypass(ctx, "errtext read", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT to_jsonb(e), request_id FROM audit_events e
			WHERE organization_id = $1 AND action = 'role.create'`, org).Scan(&raw, &reqID)
	}); err != nil {
		t.Fatalf("reading the event back: %v", err)
	}
	var row struct {
		Meta map[string]any `json:"meta"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatal(err)
	}
	if row.Meta["error"] != reqid.Message(id) {
		t.Errorf("meta.error %q, want %q", row.Meta["error"], reqid.Message(id))
	}
	if row.Meta["requestId"] != id {
		t.Errorf("meta.requestId %v, want %q", row.Meta["requestId"], id)
	}
	if reqID == nil || *reqID != id {
		t.Errorf("request_id %v, want %q", reqID, id)
	}
	for _, leak := range []string{leakyHost, leakySQL, "42501"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("the event %s leaks %q", raw, leak)
		}
	}

	var imported []byte
	if err := db.Bypass(ctx, "errtext read", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT meta FROM audit_events
			WHERE organization_id = $1 AND action = 'connector.import'`, org).Scan(&imported)
	}); err != nil {
		t.Fatalf("reading the import event back: %v", err)
	}
	var meta map[string]any
	if err := json.Unmarshal(imported, &meta); err != nil {
		t.Fatal(err)
	}
	if meta["error"] != "bad_request" || meta["message"] != nil || meta["requestId"] != id {
		t.Errorf("import meta %s, want only the code and the request id", imported)
	}
}
