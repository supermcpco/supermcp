package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
	"github.com/supermcpco/supermcp/internal/upstreamauth"
)

func TestConsentReason(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		want string
	}{
		{upstreamauth.ErrConsentInvalid, "expired"},
		{fmt.Errorf("wrapped: %w", upstreamauth.ErrNoRefreshToken), "no_refresh_token"},
		{fmt.Errorf("%w: the vendor answered 400", upstreamauth.ErrVendorRejected), "vendor_refused"},
		{upstreamauth.ErrNotAuthCode, "not_supported"},
		{connector.ErrNotFound, "unavailable"},
		{errors.New("anything else"), "connect_failed"},
	}
	for _, tt := range tests {
		if got := consentReason(tt.err); got != tt.want {
			t.Errorf("consentReason(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}

func TestConnectorPage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		id, outcome, want string
	}{
		{"c1", consentOK, "/connectors/c1?oauth=ok"},
		{"c1", "vendor_refused", "/connectors/c1?oauth=vendor_refused"},
		{"", "expired", "/connectors?oauth=expired"},
		{"a/b?x=1", consentOK, "/connectors/a%2Fb%3Fx=1?oauth=ok"},
	}
	for _, tt := range tests {
		if got := connectorPage(tt.id, tt.outcome); got != tt.want {
			t.Errorf("connectorPage(%q, %q) = %q, want %q", tt.id, tt.outcome, got, tt.want)
		}
	}
}

// fakeConsents is a ConsentStore holding the consents a test sets up.
type fakeConsents struct {
	mu sync.Mutex
	m  map[string]upstreamauth.Consent
}

func (f *fakeConsents) Create(_ context.Context, c upstreamauth.Consent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[c.State] = c
	return nil
}

func (f *fakeConsents) Consume(_ context.Context, state string) (upstreamauth.Consent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.m[state]
	if !ok {
		return upstreamauth.Consent{}, upstreamauth.ErrConsentInvalid
	}
	delete(f.m, state)
	return c, nil
}

const consentCleanup = `DELETE FROM organizations WHERE id = 'cb_a';`

// TestConnectorAuthCallbackRedirect drives the vendor's way back once for
// each outcome and checks where the browser is sent: the connector's page
// with oauth=ok or oauth=<reason>, or the connector list when the consent
// names no connector. Requires DATABASE_URL.
func TestConnectorAuthCallbackRedirect(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := openAppStore(t, dsn, log)
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}
	exec := func(sql string, args ...any) {
		t.Helper()
		if err := db.Bypass(ctx, "consent test", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}

	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_, _ = io.WriteString(w, `{"access_token":"at","refresh_token":"rt","expires_in":3600}`)
		case "/token-access-only":
			_, _ = io.WriteString(w, `{"access_token":"at","expires_in":3600}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(vendor.Close)
	authCode := func(tokenPath, clientID string) string {
		b, _ := json.Marshal(map[string]any{"type": "oauth2", "grant": "authorization_code", "clientId": clientID,
			"authorizationUrl": vendor.URL + "/authorize", "tokenUrl": vendor.URL + tokenPath})
		return string(b)
	}

	exec(consentCleanup)
	t.Cleanup(func() { exec(consentCleanup) })
	exec(`INSERT INTO organizations (id, slug, name) VALUES ('cb_a','cb-a','A')`)
	exec(`INSERT INTO connectors (id, organization_id, name, transport, auth) VALUES
		('cb_ok','cb_a','ok','{}',$1), ('cb_norefresh','cb_a','no refresh','{}',$2),
		('cb_apikey','cb_a','api key','{}','{"type":"apiKey"}'), ('cb_broken','cb_a','broken','{}',$3)`,
		authCode("/token", "cid"), authCode("/token-access-only", "cid"), authCode("/token", ""))

	kek, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "test")
	if err != nil {
		t.Fatal(err)
	}
	conns := connector.New(db, secrets.New(kek, &store.KeyStore{DB: db}), uuid.NewString)
	consents := &fakeConsents{m: map[string]upstreamauth.Consent{}}
	for state, conn := range map[string]string{"s_ok": "cb_ok", "s_refused": "cb_ok", "s_norefresh": "cb_norefresh",
		"s_apikey": "cb_apikey", "s_broken": "cb_broken", "s_gone": "cb_missing"} {
		consents.m[state] = upstreamauth.Consent{State: state, ConnectorID: conn, OrgID: "cb_a", Verifier: strings.Repeat("v", 43),
			ActorID: "someone", ExpiresAt: time.Now().Add(time.Hour)}
	}
	flow := upstreamauth.NewAuthCode(consents, vendor.Client(), nil)
	d := Deps{Log: log, DB: db, Connectors: conns}

	tests := []struct {
		name  string
		query url.Values
		want  string
	}{
		{"an unknown state", url.Values{"state": {"nope"}, "code": {"x"}}, "/connectors?oauth=expired"},
		{"no state", url.Values{"code": {"x"}}, "/connectors?oauth=expired"},
		{"the vendor refused", url.Values{"state": {"s_refused"}, "error": {"access_denied"}}, "/connectors/cb_ok?oauth=vendor_refused"},
		{"the connector is gone", url.Values{"state": {"s_gone"}, "code": {"x"}}, "/connectors/cb_missing?oauth=unavailable"},
		{"not the authorization code grant", url.Values{"state": {"s_apikey"}, "code": {"x"}}, "/connectors/cb_apikey?oauth=not_supported"},
		{"no refresh token", url.Values{"state": {"s_norefresh"}, "code": {"x"}}, "/connectors/cb_norefresh?oauth=no_refresh_token"},
		{"anything else", url.Values{"state": {"s_broken"}, "code": {"x"}}, "/connectors/cb_broken?oauth=connect_failed"},
		{"connected", url.Values{"state": {"s_ok"}, "code": {"x"}}, "/connectors/cb_ok?oauth=ok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/auth/connectors/callback?"+tt.query.Encode(), nil)
			rec := httptest.NewRecorder()
			d.connectorAuthCallback(flow, rec, req)
			if rec.Code != http.StatusFound {
				t.Fatalf("status %d, want 302: %s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Location"); got != tt.want {
				t.Errorf("Location = %q, want %q", got, tt.want)
			}
		})
	}

	// The connector that was connected now says so.
	c, err := conns.Get(ctx, "cb_a", "cb_ok")
	if err != nil {
		t.Fatal(err)
	}
	if !connectorToDTO(c).OAuthAuthorized {
		t.Error("cb_ok is not oauthAuthorized after the consent")
	}
}

// statementLog records the SQL of every statement a pool runs, whether
// sent on its own or in a batch.
type statementLog struct {
	mu   sync.Mutex
	sqls []string
}

var (
	_ pgx.QueryTracer = (*statementLog)(nil)
	_ pgx.BatchTracer = (*statementLog)(nil)
)

func (l *statementLog) add(sql string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sqls = append(l.sqls, sql)
}

func (l *statementLog) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	l.add(d.SQL)
	return ctx
}

func (l *statementLog) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (l *statementLog) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	return ctx
}

func (l *statementLog) TraceBatchQuery(_ context.Context, _ *pgx.Conn, d pgx.TraceBatchQueryData) {
	l.add(d.SQL)
}

func (l *statementLog) TraceBatchEnd(context.Context, *pgx.Conn, pgx.TraceBatchEndData) {}

func (l *statementLog) reset() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.sqls
	l.sqls = nil
	return out
}

const oauthListCleanup = `
DELETE FROM organizations WHERE id IN ('ok_a','ok_b');
DELETE FROM users WHERE id = 'ok_u_a';
`

// TestConnectorsListOAuthAuthorized checks oauthAuthorized on the
// connector list and that the list is one statement however many
// connectors there are: the token rows are read in the statement that
// reads the connectors, not one query per connector. Requires
// DATABASE_URL.
func TestConnectorsListOAuthAuthorized(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := openAppStore(t, dsn, log)
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}
	exec := func(sql string) {
		t.Helper()
		if err := db.Bypass(ctx, "oauth list test", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	exec(oauthListCleanup)
	t.Cleanup(func() { exec(oauthListCleanup) })
	exec(`
INSERT INTO users (id, email, name) VALUES ('ok_u_a','a@oauthlist.test','A');
INSERT INTO organizations (id, slug, name) VALUES ('ok_a','ok-a','A'), ('ok_b','ok-b','B');
INSERT INTO organization_members (user_id, organization_id) VALUES ('ok_u_a','ok_a');
INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id) VALUES ('ok_rb_a','ok_a','user','ok_u_a','role_viewer');
INSERT INTO connectors (id, organization_id, name, transport, auth, created_at) VALUES
    ('ok_c1','ok_a','consented','{}','{"type":"oauth2","grant":"authorization_code"}', '2026-01-01T00:00:01Z'),
    ('ok_c2','ok_a','not yet','{}','{"type":"oauth2","grant":"authorization_code"}', '2026-01-01T00:00:02Z'),
    ('ok_c3','ok_a','api key','{}','{"type":"apiKey"}', '2026-01-01T00:00:03Z'),
    ('ok_cb','ok_b','theirs','{}','{"type":"oauth2","grant":"authorization_code"}', '2026-01-01T00:00:04Z');
INSERT INTO connector_tokens (connector_id, organization_id, token_enc, expires_at) VALUES
    ('ok_c1','ok_a','\x00', now()), ('ok_c3','ok_a','\x00', now()), ('ok_cb','ok_b','\x00', now());
`)

	// The routes read through a pool of their own whose statements are
	// logged, under the same role as the app pool.
	log2 := &statementLog{}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Tracer = log2
	cfg.MaxConns = 1
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE supermcp_app")
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// One connection, opened (and its SET ROLE sent) before anything is
	// counted, so every request below reuses it.
	c, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.Release()
	counted := &tenant.DB{App: pool, Log: log}

	_, api := humatest.New(t)
	Deps{DB: counted, Authz: authz.New(db), Log: log, Connectors: connector.New(counted, nil, nil)}.connectorRoutes(api)
	list := func(t *testing.T) (map[string]bool, []string) {
		t.Helper()
		log2.reset()
		p := &authz.Principal{Kind: authz.KindUser, ID: "ok_u_a", OrgID: "ok_a", AuthMethod: "session"}
		resp := api.GetCtx(authz.WithPrincipal(ctx, p), "/api/v1/connectors")
		if resp.Code != http.StatusOK {
			t.Fatalf("status %d: %s", resp.Code, resp.Body.String())
		}
		var out []connectorDTO
		if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, c := range out {
			got[c.ID] = c.OAuthAuthorized
		}
		// Everything the request sent but the tenant's set_config, which
		// every transaction starts with.
		var sent []string
		for _, sql := range log2.reset() {
			if !strings.Contains(sql, "app.current_org") {
				sent = append(sent, sql)
			}
		}
		return got, sent
	}

	got, reads := list(t)
	want := map[string]bool{"ok_c1": true, "ok_c2": false, "ok_c3": false}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("three connectors: got %v, want %v", got, want)
	}
	wantSent(t, "three connectors", reads)

	exec(`
INSERT INTO connectors (id, organization_id, name, transport, auth) VALUES
    ('ok_c4','ok_a','client credentials','{}','{"type":"oauth2","grant":"client_credentials"}'),
    ('ok_c5','ok_a','none','{}','{}'),
    ('ok_c6','ok_a','not yet either','{}','{"type":"oauth2","grant":"authorization_code"}');
INSERT INTO connector_tokens (connector_id, organization_id, token_enc, expires_at) VALUES ('ok_c4','ok_a','\x00', now());
`)
	got, reads = list(t)
	want = map[string]bool{"ok_c1": true, "ok_c2": false, "ok_c3": false, "ok_c4": true, "ok_c5": false, "ok_c6": false}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("six connectors: got %v, want %v", got, want)
	}
	wantSent(t, "six connectors", reads)
}

// wantSent checks that listing connectors sent one transaction holding
// one statement: the connectors with their tool counts and token rows.
func wantSent(t *testing.T, what string, sent []string) {
	t.Helper()
	if len(sent) != 3 || !strings.EqualFold(sent[0], "begin") || !strings.Contains(sent[1], "FROM connectors") ||
		!strings.Contains(sent[1], "connector_tokens") || !strings.EqualFold(sent[2], "commit") {
		t.Errorf("%s sent %d statements, want begin, one select, commit: %q", what, len(sent), sent)
	}
}
