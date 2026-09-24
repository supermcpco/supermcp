// Package e2e drives the whole stack over HTTP: the admin API, the MCP
// endpoint and a real MCP client, against a real Postgres and a fake
// upstream. It is skipped unless DATABASE_URL is set.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/catalog"
	"github.com/supermcpco/supermcp/internal/config"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/dbpool"
	"github.com/supermcpco/supermcp/internal/httpapi"
	"github.com/supermcpco/supermcp/internal/httpclient"
	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/identity/sso"
	"github.com/supermcpco/supermcp/internal/invoke"
	mcpendpoint "github.com/supermcpco/supermcp/internal/mcp"
	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/mcpserver"
	"github.com/supermcpco/supermcp/internal/scim"
	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/ssrf"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

func newID() string {
	id, err := uuid.NewV7()
	if err != nil {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}
	return id.String()
}

type harness struct {
	url        string
	client     *http.Client
	cookie     string
	deps       httpapi.Deps
	connectors *connector.Service
	servers    *mcpserver.Service
	db         *tenant.DB
}

func start(t *testing.T) *harness {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	mst, err := store.Open(ctx, dsn, dsn, log, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := mst.Migrate(ctx, true); err != nil {
		t.Fatal(err)
	}
	mst.Close()

	st, err := store.Open(ctx, dsn, dsn, log, store.Options{AppRole: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}
	kek, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "test")
	if err != nil {
		t.Fatal(err)
	}
	sealer := secrets.New(kek, &store.KeyStore{DB: db})
	dialer := ssrf.NewDialer(&ssrf.Policy{AllowLoopback: true}) // the fake upstream is on loopback
	clients := httpclient.NewFactory(dialer)
	pools := dbpool.New(dialer, 10)
	t.Cleanup(pools.Close)

	auditor := audit.NewWriter(db, log, audit.Options{})
	t.Cleanup(auditor.Close)
	policies := audit.NewPolicies(db)

	az := authz.New(db)
	ids := identity.New(db, identity.Config{OpenRegistration: true}, az, newID)
	keys := mcpauth.New(db, newID)
	conns := connector.New(db, sealer, newID)
	servers := mcpserver.New(db, conns, newID)
	exec := invoke.New(invoke.Deps{DB: db, Connectors: conns, Clients: clients, Pools: pools, Log: log, NewID: newID,
		Audit: auditor, Policies: policies})
	keyring := mcpauth.NewKeyring(db, sealer, newID)
	oauth := mcpauth.NewOAuth(db, keyring, "http://127.0.0.1", mcpauth.DCROpen, newID)
	oauth.Accounts = ids
	endpoint := mcpendpoint.New(mcpendpoint.Deps{Servers: servers, Authz: az, Executor: exec, Log: log, Version: "test"})

	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load("test")
	if err != nil {
		// config.Load needs env; build one directly for the test.
		cfg = &config.Config{Version: "test", Dev: true, LogLevel: "error", LogFormat: "text"}
	}
	cfg.Dev = true
	// The public URL has to be the address this server will answer on: the
	// single sign-on redirect URI is built from it, and a provider sends
	// the browser back there.
	srv := httptest.NewUnstartedServer(nil)
	cfg.PublicURL = mustURL("http://" + srv.Listener.Addr().String())
	idpClient := httpclient.New(dialer, "identity-providers", httpclient.DefaultPolicy())
	provisioning := scim.New(db, ids, az, newID)
	provisioning.Audit = auditor
	deps := httpapi.Deps{Config: cfg, Log: log, Store: st, Catalog: cat, DB: db, Identity: ids,
		Authz: az, Keys: keys, Connectors: conns, Servers: servers, MCP: endpoint, OAuth: oauth, OpenRegistration: true,
		SSO:   sso.New(db, sealer, idpClient, newID, cfg.PublicURL),
		SCIM:  provisioning,
		Audit: auditor, AuditReader: &audit.Reader{DB: db}, AuditPolicies: policies}
	handler, _ := httpapi.New(deps)
	srv.Config.Handler = handler
	srv.Start()
	t.Cleanup(srv.Close)

	return &harness{url: srv.URL, client: srv.Client(), deps: deps, connectors: conns, servers: servers, db: db}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func (h *harness) do(t *testing.T, method, path string, body any, out any) int {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, h.url+path, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if h.cookie != "" {
		req.Header.Set("Cookie", h.cookie)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if sc := resp.Header.Get("Set-Cookie"); sc != "" {
		h.cookie = strings.Split(sc, ";")[0]
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && resp.StatusCode < 300 {
			t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

// fakeUpstream serves a tiny API the test connector points at.
func fakeUpstream(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-Api-Key") != "secret-value" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"bad key"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + r.URL.Query().Get("id") + `","name":"Widget","price":9.5}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func testConnector(t *testing.T, upstream string) connector.CreateInput {
	t.Helper()
	input, err := adapter.NodeFromJSON([]byte(`{"type":"object","properties":{"id":{"type":"string","description":"Item id"}},"required":["id"]}`))
	if err != nil {
		t.Fatal(err)
	}
	query, err := adapter.NodeFromJSON([]byte(`{"id":"{{params.id}}"}`))
	if err != nil {
		t.Fatal(err)
	}
	return connector.CreateInput{
		Name:      "Fake API",
		Transport: adapter.Transport{Type: adapter.TransportHTTP, BaseURL: upstream},
		Auth:      adapter.Auth{Type: adapter.AuthAPIKey, In: "header", Name: "X-Api-Key", Value: "{{env.FAKE_KEY}}"},
		Tools: []adapter.Tool{{
			Name: "fake_get_item", Description: "Fetch one item by id from the fake API for testing.",
			Input:     input,
			Operation: adapter.Operation{Method: "GET", Path: "/items", Query: query},
		}},
		Credentials: map[string]string{"FAKE_KEY": "secret-value"},
	}
}

// TestEndToEnd registers an account, creates a connector and an MCP
// server, mints an API key and drives the MCP endpoint with a real client.
func TestEndToEnd(t *testing.T) {
	h := start(t)
	upstream, calls := fakeUpstream(t)
	ctx := context.Background()

	email := newID() + "@e2e.test"
	var session struct {
		User struct{ ID, Email string } `json:"user"`
		Org  struct{ ID, Slug string }  `json:"organization"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email": email, "password": "correct horse battery 9", "orgName": "E2E",
	}, &session); code != 200 {
		t.Fatalf("register: %d", code)
	}
	orgID := session.Org.ID
	octx := tenant.WithOrg(ctx, orgID)

	c, err := h.connectors.Create(octx, orgID, testConnector(t, upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := h.servers.Create(octx, orgID, "E2E server", "", "Use the fake API.", []string{c.ID}, session.User.ID)
	if err != nil {
		t.Fatal(err)
	}

	var keyResp struct {
		Secret string `json:"secret"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/api-keys", map[string]any{"name": "e2e"}, &keyResp); code != 200 || keyResp.Secret == "" {
		t.Fatalf("create key: %d %q", code, keyResp.Secret)
	}

	// Drive the MCP endpoint with the SDK client.
	transport := &sdk.StreamableClientTransport{
		Endpoint:   h.url + "/mcp/" + srv.ID,
		HTTPClient: &http.Client{Transport: &keyRoundTripper{key: keyResp.Secret, base: h.client.Transport}},
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "e2e", Version: "1"}, nil)
	sess, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = sess.Close() }()

	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "fake_get_item" {
		t.Fatalf("tools: %+v", tools.Tools)
	}
	if !tools.Tools[0].Annotations.ReadOnlyHint {
		t.Error("GET tool should be read-only")
	}
	// The credential must not appear in the served schema.
	schema, _ := json.Marshal(tools.Tools[0].InputSchema)
	if strings.Contains(string(schema), "FAKE_KEY") || strings.Contains(string(schema), "secret-value") {
		t.Errorf("schema leaks credentials: %s", schema)
	}

	res, err := sess.CallTool(ctx, &sdk.CallToolParams{Name: "fake_get_item", Arguments: map[string]any{"id": "42"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("call failed: %+v", res.Content)
	}
	text := res.Content[0].(*sdk.TextContent).Text
	if !strings.Contains(text, `"id": "42"`) || !strings.Contains(text, "Widget") {
		t.Fatalf("unexpected result: %s", text)
	}
	if *calls != 1 {
		t.Errorf("upstream called %d times", *calls)
	}

	// An unknown tool is refused without revealing whether it exists.
	if _, err := sess.CallTool(ctx, &sdk.CallToolParams{Name: "other_tool"}); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Errorf("hidden tool: %v", err)
	}

	// The call was recorded.
	var invocations []struct {
		ToolName string `json:"toolName"`
		Status   string `json:"status"`
	}
	if code := h.do(t, http.MethodGet, "/api/v1/tool-calls", nil, &invocations); code != 200 {
		t.Fatalf("tool-calls: %d", code)
	}
	if len(invocations) != 1 || invocations[0].ToolName != "fake_get_item" || invocations[0].Status != "success" {
		t.Fatalf("invocations: %+v", invocations)
	}

	// A second organisation cannot reach the first one's server, even with
	// a valid key of its own.
	other := start(t)
	other.url, other.client = h.url, h.client // same server, new session
	var otherSession struct {
		Org struct{ ID string } `json:"organization"`
	}
	if code := other.do(t, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email": newID() + "@e2e.test", "password": "correct horse battery 9", "orgName": "Other",
	}, &otherSession); code != 200 {
		t.Fatalf("register other: %d", code)
	}
	var otherKey struct {
		Secret string `json:"secret"`
	}
	other.do(t, http.MethodPost, "/api/v1/api-keys", map[string]any{"name": "other"}, &otherKey)
	req, _ := http.NewRequest(http.MethodPost, h.url+"/mcp/"+srv.ID, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("X-API-Key", otherKey.Secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("cross-tenant access: %d %s", resp.StatusCode, body)
	}

	// The other tenant also cannot see the first tenant's connectors.
	var list []map[string]any
	other.do(t, http.MethodGet, "/api/v1/connectors", nil, &list)
	if len(list) != 0 {
		t.Fatalf("cross-tenant connectors visible: %+v", list)
	}

	// Cleanup.
	_ = h.db.Bypass(ctx, "e2e cleanup", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM tool_invocations WHERE organization_id = $1; DELETE FROM organizations WHERE id IN ($1, $2)`, orgID, otherSession.Org.ID)
		return err
	})
}

// keyRoundTripper adds the API key to every MCP request.
type keyRoundTripper struct {
	key  string
	base http.RoundTripper
}

func (k *keyRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-API-Key", k.key)
	base := k.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}

// TestOAuthFlow drives the authorization code flow the way an MCP client
// does: discover, register, authorize with PKCE, consent, exchange, then
// call the MCP endpoint with the token and refresh it.
func TestOAuthFlow(t *testing.T) {
	h := start(t)
	upstream, _ := fakeUpstream(t)
	ctx := context.Background()

	var session struct {
		User struct{ ID string } `json:"user"`
		Org  struct{ ID string } `json:"organization"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email": newID() + "@oauth.test", "password": "correct horse battery 9", "orgName": "OAuth",
	}, &session); code != 200 {
		t.Fatalf("register: %d", code)
	}
	octx := tenant.WithOrg(ctx, session.Org.ID)
	c, err := h.connectors.Create(octx, session.Org.ID, testConnector(t, upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := h.servers.Create(octx, session.Org.ID, "OAuth server", "", "", []string{c.ID}, session.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = h.db.Bypass(ctx, "oauth test cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM tool_invocations WHERE organization_id = $1; DELETE FROM organizations WHERE id = $1`, session.Org.ID)
			return err
		})
	})

	// Discovery.
	var meta map[string]any
	if code := h.do(t, http.MethodGet, "/.well-known/oauth-authorization-server", nil, &meta); code != 200 {
		t.Fatalf("metadata: %d", code)
	}
	for _, key := range []string{"authorization_endpoint", "token_endpoint", "registration_endpoint", "jwks_uri", "revocation_endpoint", "introspection_endpoint"} {
		if meta[key] == nil {
			t.Errorf("metadata missing %s", key)
		}
	}
	if methods, _ := meta["code_challenge_methods_supported"].([]any); len(methods) != 1 || methods[0] != "S256" {
		t.Errorf("PKCE methods: %v", meta["code_challenge_methods_supported"])
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if code := h.do(t, http.MethodGet, "/.well-known/jwks.json", nil, &jwks); code != 200 || len(jwks.Keys) == 0 {
		t.Fatalf("jwks: %d %+v", code, jwks)
	}

	// Registration.
	var client struct {
		ClientID string `json:"client_id"`
	}
	if code := h.do(t, http.MethodPost, "/oauth/register", map[string]any{
		"client_name": "Test Client", "redirect_uris": []string{"http://127.0.0.1:7777/callback"},
	}, &client); code != 201 || client.ClientID == "" {
		t.Fatalf("register client: %d %+v", code, client)
	}
	// A wildcard or non-loopback http redirect is refused.
	var bad map[string]any
	if code := h.do(t, http.MethodPost, "/oauth/register", map[string]any{"redirect_uris": []string{"http://evil.example/cb"}}, &bad); code != 400 {
		t.Errorf("non-loopback http redirect accepted: %d", code)
	}

	// Authorize: PKCE is mandatory.
	verifier := "test-verifier-" + newID() + newID()
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{"response_type": {"code"}, "client_id": {client.ClientID},
		"redirect_uri": {"http://127.0.0.1:7777/callback"}, "state": {"xyz"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"scope":    {"mcp:tools:read mcp:tools:invoke offline_access"},
		"resource": {h.url + "/mcp/" + srv.ID}}

	noPKCE := url.Values{}
	for k, v := range q {
		noPKCE[k] = v
	}
	noPKCE.Del("code_challenge")
	if code := h.do(t, http.MethodGet, "/oauth/authorize?"+noPKCE.Encode(), nil, nil); code != 400 {
		t.Errorf("authorize without PKCE: %d", code)
	}

	getCode := func() string {
		t.Helper()
		page := h.getString(t, "/oauth/authorize?"+q.Encode())
		id := between(page, `name="request_id" value="`, `"`)
		if id == "" {
			t.Fatalf("no request id on the consent page: %s", page)
		}
		form := url.Values{"request_id": {id}, "decision": {"allow"}}
		req, _ := http.NewRequest(http.MethodPost, h.url+"/oauth/consent", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Cookie", h.cookie)
		noRedirect := *h.client
		noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("consent: %d", resp.StatusCode)
		}
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if loc.Query().Get("state") != "xyz" || loc.Query().Get("iss") == "" {
			t.Fatalf("redirect missing state or iss: %s", loc)
		}
		return loc.Query().Get("code")
	}

	page := h.getString(t, "/oauth/authorize?"+q.Encode())
	if !strings.Contains(page, "Test Client") || !strings.Contains(page, "Call those tools") {
		t.Fatalf("consent page: %s", page)
	}
	if between(page, `name="request_id" value="`, `"`) == "" {
		t.Fatal("no request id on the consent page")
	}

	// Exchange, with the wrong verifier first.
	exchange := func(v url.Values) (map[string]any, int) {
		req, _ := http.NewRequest(http.MethodPost, h.url+"/oauth/token", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out, resp.StatusCode
	}
	if _, status := exchange(url.Values{"grant_type": {"authorization_code"}, "code": {getCode()},
		"code_verifier": {"wrong"}, "client_id": {client.ClientID}, "redirect_uri": {"http://127.0.0.1:7777/callback"}}); status != 400 {
		t.Errorf("wrong verifier accepted: %d", status)
	}
	code := getCode()
	tok, status := exchange(url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"code_verifier": {verifier}, "client_id": {client.ClientID}, "redirect_uri": {"http://127.0.0.1:7777/callback"}})
	if status != 200 {
		t.Fatalf("token: %d %v", status, tok)
	}
	access, _ := tok["access_token"].(string)
	refresh, _ := tok["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("token response: %v", tok)
	}
	// The code cannot be replayed.
	if _, status := exchange(url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"code_verifier": {verifier}, "client_id": {client.ClientID}}); status != 400 {
		t.Error("authorization code replay accepted")
	}

	// Use the access token against the MCP endpoint.
	transport := &sdk.StreamableClientTransport{
		Endpoint:   h.url + "/mcp/" + srv.ID,
		HTTPClient: &http.Client{Transport: &bearerRoundTripper{token: access}},
	}
	mc := sdk.NewClient(&sdk.Implementation{Name: "oauth-e2e", Version: "1"}, nil)
	msess, err := mc.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect with token: %v", err)
	}
	defer func() { _ = msess.Close() }()
	res, err := msess.CallTool(ctx, &sdk.CallToolParams{Name: "fake_get_item", Arguments: map[string]any{"id": "7"}})
	if err != nil || res.IsError {
		t.Fatalf("call with token: %v %+v", err, res)
	}

	// Refresh rotates; the old token is then dead and burns the family.
	rotated, status := exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {client.ClientID}})
	if status != 200 || rotated["refresh_token"] == refresh {
		t.Fatalf("refresh: %d %v", status, rotated)
	}
	if _, status := exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {client.ClientID}}); status != 400 {
		t.Error("reused refresh token accepted")
	}
	newRefresh, _ := rotated["refresh_token"].(string)
	if _, status := exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {newRefresh}, "client_id": {client.ClientID}}); status != 400 {
		t.Error("family was not revoked after refresh token reuse")
	}

	// A client revoking its own refresh token (RFC 7009).
	fresh, status := exchange(url.Values{"grant_type": {"authorization_code"}, "code": {getCode()},
		"code_verifier": {verifier}, "client_id": {client.ClientID}, "redirect_uri": {"http://127.0.0.1:7777/callback"}})
	if status != 200 {
		t.Fatalf("second token: %d %v", status, fresh)
	}
	freshRefresh, _ := fresh["refresh_token"].(string)
	revokeReq, _ := http.NewRequest(http.MethodPost, h.url+"/oauth/revoke",
		strings.NewReader(url.Values{"token": {freshRefresh}}.Encode()))
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, err := h.client.Do(revokeReq); err != nil || resp.StatusCode != 200 {
		t.Fatalf("revoke: %v", err)
	} else {
		resp.Body.Close()
	}

	// All of it is on the audit trail: the grant and the tokens against the
	// workspace, the replay as a denial against the person whose tokens it
	// burned, and what happened before any workspace was known against the
	// client.
	outcomes := map[string][]string{}
	for _, e := range h.auditEvents(t, octx, session.Org.ID) {
		if strings.HasPrefix(e.Action, "oauth.") {
			outcomes[e.Action] = append(outcomes[e.Action], e.Outcome)
			if e.Action == "oauth.token" && e.ActorID != session.User.ID {
				t.Errorf("a token was recorded as issued to %q, want the signed-in user %q", e.ActorID, session.User.ID)
			}
		}
	}
	for action, want := range map[string]string{
		"oauth.consent.grant": audit.Success,
		"oauth.token":         audit.Success,
		"oauth.refresh.reuse": audit.Denied,
		"oauth.token.revoke":  audit.Success,
	} {
		if !slices.Contains(outcomes[action], want) {
			t.Errorf("no %s event with outcome %s on the trail; got %v", action, want, outcomes)
		}
	}
	var registered, refused int
	if err := h.db.Bypass(octx, "e2e oauth audit", func(tx pgx.Tx) error {
		if err := tx.QueryRow(octx, `SELECT count(*) FROM audit_events WHERE action = 'oauth.client.register'
			AND outcome = 'success' AND target_id = $1`, client.ClientID).Scan(&registered); err != nil {
			return err
		}
		return tx.QueryRow(octx, `SELECT count(*) FROM audit_events WHERE action = 'oauth.token'
			AND outcome = 'failure' AND actor_id = $1 AND meta->>'error' = 'invalid_grant'`, client.ClientID).Scan(&refused)
	}); err != nil {
		t.Fatal(err)
	}
	if registered != 1 {
		t.Errorf("the client's registration was recorded %d times, want once", registered)
	}
	// The wrong verifier and the replayed code.
	if refused < 2 {
		t.Errorf("%d refused token requests recorded for the client, want at least the wrong verifier and the replayed code", refused)
	}

	// A token for this server is refused by another server's endpoint.
	otherSrv, err := h.servers.Create(octx, session.Org.ID, "Other server", "", "", nil, session.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	req2, _ := http.NewRequest(http.MethodPost, h.url+"/mcp/"+otherSrv.ID, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req2.Header.Set("Authorization", "Bearer "+access)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Accept", "application/json, text/event-stream")
	resp2, err := h.client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("token bound to one server worked on another: %d", resp2.StatusCode)
	}

	// An unauthenticated request advertises where to get a token.
	req3, _ := http.NewRequest(http.MethodPost, h.url+"/mcp/"+srv.ID, strings.NewReader(`{}`))
	req3.Header.Set("Content-Type", "application/json")
	resp3, err := h.client.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if challenge := resp3.Header.Get("WWW-Authenticate"); !strings.Contains(challenge, "resource_metadata=") {
		t.Errorf("no resource metadata challenge: %q", challenge)
	}
}

func (h *harness) getString(t *testing.T, path string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.url+path, nil)
	req.Header.Set("Cookie", h.cookie)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

type bearerRoundTripper struct{ token string }

func (b *bearerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}
