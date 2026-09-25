package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// oauthClient walks the authorization code grant for one registered
// client against one server, as the signed-in person of h.
type oauthClient struct {
	h        *harness
	clientID string
	serverID string
	verifier string
}

func newOAuthClient(t *testing.T, h *harness, orgID, userID string) *oauthClient {
	t.Helper()
	ctx := tenant.WithOrg(context.Background(), orgID)
	srv, err := h.servers.Create(ctx, orgID, "Session server", "", "", nil, userID)
	if err != nil {
		t.Fatal(err)
	}
	var client struct {
		ClientID string `json:"client_id"`
	}
	if code := h.do(t, http.MethodPost, "/oauth/register", map[string]any{
		"client_name": "Session Client", "redirect_uris": []string{"http://127.0.0.1:7777/callback"},
	}, &client); code != http.StatusCreated {
		t.Fatalf("register client: %d", code)
	}
	return &oauthClient{h: h, clientID: client.ClientID, serverID: srv.ID, verifier: "verifier-" + newID() + newID()}
}

// code consents in the harness's current session and returns the code.
func (c *oauthClient) code(t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256([]byte(c.verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {c.clientID},
		"redirect_uri": {"http://127.0.0.1:7777/callback"}, "state": {"s"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"scope":    {"mcp:tools:read offline_access"},
		"resource": {c.h.url + "/mcp/" + c.serverID}}
	page := c.h.getString(t, "/oauth/authorize?"+q.Encode())
	id := between(page, `name="request_id" value="`, `"`)
	if id == "" {
		t.Fatalf("no request id on the consent page: %s", page)
	}
	form := url.Values{"request_id": {id}, "decision": {"allow"}}
	req, err := http.NewRequest(http.MethodPost, c.h.url+"/oauth/consent", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", c.h.cookie)
	noRedirect := *c.h.client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("consent: %d %v", resp.StatusCode, err)
	}
	return loc.Query().Get("code")
}

// token posts a grant to the token endpoint.
func (c *oauthClient) token(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	form.Set("client_id", c.clientID)
	req, err := http.NewRequest(http.MethodPost, c.h.url+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// grant runs consent and the code exchange, returning the access and
// refresh tokens.
func (c *oauthClient) grant(t *testing.T) (string, string) {
	t.Helper()
	status, body := c.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {c.code(t)},
		"code_verifier": {c.verifier}, "redirect_uri": {"http://127.0.0.1:7777/callback"}})
	access, _ := body["access_token"].(string)
	refresh, _ := body["refresh_token"].(string)
	if status != http.StatusOK || access == "" || refresh == "" {
		t.Fatalf("code exchange: %d %v", status, body)
	}
	return access, refresh
}

// jwtClaims reads an access token's claims without checking the
// signature; the server checks that.
func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func claimAMR(claims map[string]any) []string {
	list, _ := claims["amr"].([]any)
	out := []string{}
	for _, v := range list {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// sessionOf is the stored id of the session the harness's cookie carries.
func sessionOf(t *testing.T, h *harness) string {
	t.Helper()
	_, secret, ok := strings.Cut(h.cookie, "=")
	if !ok || secret == "" {
		t.Fatalf("the harness holds no session cookie: %q", h.cookie)
	}
	return identity.SessionKey(secret)
}

// introspector returns a function that introspects a token with an API
// key of the given person.
func introspector(t *testing.T, h *harness, orgID, userID string) func(token string) mcpauth.Introspection {
	t.Helper()
	ctx := context.Background()
	_, key, err := h.deps.Keys.Create(ctx, mcpauth.CreateInput{OrgID: orgID, PrincipalKind: "user",
		PrincipalID: userID, Name: "resource server", CreatedBy: userID})
	if err != nil {
		t.Fatal(err)
	}
	return func(token string) mcpauth.Introspection {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url+"/oauth/introspect",
			strings.NewReader(url.Values{"token": {token}}.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-API-Key", key)
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out mcpauth.Introspection
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("introspect: %d %v", resp.StatusCode, err)
		}
		return out
	}
}

// TestOAuthTokenNamesItsSession checks the sid and amr claims: a code
// grant carries the consenting session and how it signed in, through
// refresh and introspection; client credentials carry neither.
func TestOAuthTokenNamesItsSession(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	admin := h.register(t, "E2E OAuth session claims")
	sid := sessionOf(t, h)
	c := newOAuthClient(t, h, admin.Org.ID, admin.User.ID)
	introspect := introspector(t, h, admin.Org.ID, admin.User.ID)

	// A password session.
	access, refresh := c.grant(t)
	claims := jwtClaims(t, access)
	if claims["sid"] != sid {
		t.Errorf("sid = %v, want the consenting session %s", claims["sid"], sid)
	}
	if got := claimAMR(claims); !slices.Equal(got, []string{"pwd"}) {
		t.Errorf("amr = %v, want [pwd]", got)
	}
	in := introspect(access)
	if !in.Active || in.Sid != sid || !slices.Equal(in.AMR, []string{"pwd"}) {
		t.Errorf("introspection = %+v, want active with sid %s and amr [pwd]", in, sid)
	}

	// Refreshing keeps both.
	status, body := c.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
	if status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, body)
	}
	rotated, _ := body["access_token"].(string)
	if rc := jwtClaims(t, rotated); rc["sid"] != sid || !slices.Equal(claimAMR(rc), []string{"pwd"}) {
		t.Errorf("after refresh sid = %v amr = %v, want %s [pwd]", rc["sid"], claimAMR(rc), sid)
	}

	// The same session once a second factor is on record.
	if err := h.deps.Identity.MarkVerified(ctx, sid); err != nil {
		t.Fatal(err)
	}
	mfaAccess, _ := c.grant(t)
	if got := claimAMR(jwtClaims(t, mfaAccess)); !slices.Equal(got, []string{"pwd", "mfa"}) {
		t.Errorf("amr after a verified factor = %v, want [pwd mfa]", got)
	}
	if in := introspect(mfaAccess); !slices.Equal(in.AMR, []string{"pwd", "mfa"}) {
		t.Errorf("introspected amr = %v, want [pwd mfa]", in.AMR)
	}

	// Client credentials: no session, no sign-in.
	var sa struct {
		ClientID string `json:"clientId"`
		Secret   string `json:"secret"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/service-accounts", map[string]any{
		"name": "pipeline", "scopes": []string{"mcp:tools:invoke"},
	}, &sa); code != http.StatusCreated {
		t.Fatalf("create service account: %d", code)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url+"/oauth/token",
		strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(sa.ClientID, sa.Secret)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var cc struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&cc)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || cc.AccessToken == "" {
		t.Fatalf("client credentials: %d", resp.StatusCode)
	}
	ccClaims := jwtClaims(t, cc.AccessToken)
	if _, ok := ccClaims["sid"]; ok {
		t.Errorf("a client credentials token names a session: %v", ccClaims["sid"])
	}
	if _, ok := ccClaims["amr"]; ok {
		t.Errorf("a client credentials token names sign-in methods: %v", ccClaims["amr"])
	}
	if in := introspect(cc.AccessToken); !in.Active || in.Sid != "" || in.AMR != nil {
		t.Errorf("introspection of a client credentials token = %+v, want active without sid or amr", in)
	}
}

// TestEndingSessionEndsItsTokens checks that signing out revokes the
// refresh tokens the session consented to and refuses its access tokens
// at once, before they expire.
func TestEndingSessionEndsItsTokens(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	admin := h.register(t, "E2E OAuth session end")
	sid := sessionOf(t, h)
	c := newOAuthClient(t, h, admin.Org.ID, admin.User.ID)
	introspect := introspector(t, h, admin.Org.ID, admin.User.ID)

	access, refresh := c.grant(t)
	if _, err := h.deps.OAuth.PrincipalFromToken(ctx, access); err != nil {
		t.Fatalf("a fresh access token is refused: %v", err)
	}
	if code := h.do(t, http.MethodPost, "/api/v1/auth/logout", nil, nil); code != http.StatusOK {
		t.Fatalf("logout: %d", code)
	}
	if _, err := h.deps.OAuth.PrincipalFromToken(ctx, access); err == nil {
		t.Error("an access token of a signed-out session is still accepted")
	}
	if in := introspect(access); in.Active {
		t.Errorf("introspection says an access token of a signed-out session is active: %+v", in)
	}
	status, body := c.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("refresh after sign-out: %d %v, want 400 invalid_grant", status, body)
	}
	if n := liveRefreshTokens(t, h, sid); n != 0 {
		t.Errorf("%d refresh tokens of the signed-out session are still live", n)
	}
}

func liveRefreshTokens(t *testing.T, h *harness, sessionID string) int {
	t.Helper()
	ctx := context.Background()
	var n int
	if err := h.db.Bypass(ctx, "e2e session tokens", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM oauth_refresh_tokens
			WHERE session_id = $1 AND revoked_at IS NULL AND consumed_at IS NULL`, sessionID).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestSSOReauthKeepsOAuthTokens re-authenticates a single sign-on session
// that had connected a client. The new session takes over the client's
// refresh tokens rather than ending them with the old one; the old
// session's access token is refused, and the client refreshes into one
// naming the new session. An OpenID Connect session claims no "mfa".
func TestSSOReauthKeepsOAuthTokens(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	b, admin := newSSOBrowser(t, h, "E2E SSO reauth OAuth")
	b.idp.authTime = func() int64 { return time.Now().Unix() }
	if end := b.follow(t, "/auth/sso/"+b.prov.ID+"/start?next=/connectors"); end.Path != "/connectors" {
		t.Fatalf("the sign-in ended at %s", end)
	}
	first := b.session()
	var sess ssoSignInView
	if code := first.do(t, http.MethodGet, "/api/v1/auth/session", nil, &sess); code != http.StatusOK {
		t.Fatalf("session: %d", code)
	}
	c := newOAuthClient(t, h, admin.Org.ID, admin.User.ID)
	c.h = first
	access, refresh := c.grant(t)
	claims := jwtClaims(t, access)
	oldSID, _ := claims["sid"].(string)
	if oldSID == "" {
		t.Fatal("a token from a single sign-on session names no session")
	}
	if _, ok := claims["amr"]; ok {
		t.Errorf("an OpenID Connect session's token claims amr %v", claims["amr"])
	}

	h.ageSessions(t, sess.User.ID)
	if end := b.follow(t, sess.SignIn.ReauthURL+"&next=/connectors"); end.Path != "/connectors" {
		t.Fatalf("the re-authentication ended at %s", end)
	}
	if n := h.replacedCount(t, sess.User.ID); n != 1 {
		t.Fatalf("%d sessions were ended as replaced, want 1", n)
	}
	if _, err := h.deps.OAuth.PrincipalFromToken(ctx, access); err == nil {
		t.Error("an access token naming the replaced session is still accepted")
	}
	status, body := c.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
	if status != http.StatusOK {
		t.Fatalf("refresh after the session was replaced: %d %v", status, body)
	}
	renewed, _ := body["access_token"].(string)
	newSID, _ := jwtClaims(t, renewed)["sid"].(string)
	if newSID == "" || newSID == oldSID {
		t.Fatalf("after replacement sid = %q, want the new session", newSID)
	}
	if _, err := h.deps.OAuth.PrincipalFromToken(ctx, renewed); err != nil {
		t.Fatalf("the access token of the new session is refused: %v", err)
	}
	if n := liveRefreshTokens(t, h, newSID); n != 1 {
		t.Errorf("the new session holds %d live refresh tokens, want 1", n)
	}
}
