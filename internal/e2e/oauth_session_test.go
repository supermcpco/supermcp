package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
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

// sessionOf returns the stored id of the session the harness's cookie
// carries, and its public id, which a token's sid claim shows.
func sessionOf(t *testing.T, h *harness) (key, public string) {
	t.Helper()
	_, secret, ok := strings.Cut(h.cookie, "=")
	if !ok || secret == "" {
		t.Fatalf("the harness holds no session cookie: %q", h.cookie)
	}
	var list struct {
		Current string `json:"current"`
	}
	if code := h.do(t, http.MethodGet, "/api/v1/auth/sessions", nil, &list); code != http.StatusOK || list.Current == "" {
		t.Fatalf("sessions: %d %+v", code, list)
	}
	return identity.SessionKey(secret), list.Current
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
	key, sid := sessionOf(t, h)
	c := newOAuthClient(t, h, admin.Org.ID, admin.User.ID)
	introspect := introspector(t, h, admin.Org.ID, admin.User.ID)

	// A password session.
	access, refresh := c.grant(t)
	claims := jwtClaims(t, access)
	if claims["sid"] != sid {
		t.Errorf("sid = %v, want the consenting session's public id %s", claims["sid"], sid)
	}
	if claims["sid"] == key {
		t.Error("the sid claim is the session's stored id, which must not leave the server")
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
	if err := h.deps.Identity.MarkVerified(ctx, key); err != nil {
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
	_, sid := sessionOf(t, h)
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

// liveRefreshTokens counts the usable refresh tokens of the session with
// this public id.
func liveRefreshTokens(t *testing.T, h *harness, publicID string) int {
	t.Helper()
	ctx := context.Background()
	var n int
	if err := h.db.Bypass(ctx, "e2e session tokens", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM oauth_refresh_tokens
			WHERE session_id = (SELECT id FROM sessions WHERE public_id = $1)
			  AND revoked_at IS NULL AND consumed_at IS NULL`, publicID).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// liveInFamily counts the usable refresh tokens of the family the given
// refresh token belongs to.
func liveInFamily(t *testing.T, h *harness, refresh string) int {
	t.Helper()
	ctx := context.Background()
	sum := sha256.Sum256([]byte(refresh))
	var n int
	if err := h.db.Bypass(ctx, "e2e family tokens", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM oauth_refresh_tokens
			WHERE family_id = (SELECT family_id FROM oauth_refresh_tokens WHERE token_hash = $1)
			  AND revoked_at IS NULL AND consumed_at IS NULL`, sum[:]).Scan(&n)
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

// grantFor runs the code grant straight through the authorization server
// for a session the test opened, without the browser, and returns the
// access and refresh tokens.
func (c *oauthClient) grantFor(t *testing.T, sess *identity.Session) (string, string) {
	t.Helper()
	ctx := context.Background()
	sum := sha256.Sum256([]byte(c.verifier))
	req, err := c.h.deps.OAuth.BeginAuthorization(ctx, url.Values{"response_type": {"code"}, "client_id": {c.clientID},
		"redirect_uri": {"http://127.0.0.1:7777/callback"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"}, "scope": {"mcp:tools:read offline_access"},
		"resource": {c.h.url + "/mcp/" + c.serverID}})
	if err != nil {
		t.Fatal(err)
	}
	loc, err := c.h.deps.OAuth.Approve(ctx, req, mcpauth.Consent{UserID: sess.UserID, OrgID: sess.OrgID,
		ServerID: c.serverID, SessionID: sess.ID, AMR: []string{"pwd"}})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.h.deps.OAuth.Token(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")},
		"code_verifier": {c.verifier}}, c.clientID, "")
	if err != nil || res.RefreshToken == "" {
		t.Fatalf("code exchange: %v %+v", err, res)
	}
	return res.AccessToken, res.RefreshToken
}

// TestRefreshRacingSessionEnd rotates a refresh token while its session
// is being ended, many times over. Whichever wins, nothing usable is left:
// no live refresh token in the family, and a token the rotation did hand
// out is refused. A lost race used to leave a live child the revocation
// never saw.
func TestRefreshRacingSessionEnd(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	admin := h.register(t, "E2E OAuth refresh race")
	c := newOAuthClient(t, h, admin.Org.ID, admin.User.ID)

	for i := range 25 {
		sess, err := h.deps.Identity.CreateSession(ctx, admin.User.ID, admin.Org.ID, "password", "", nil, time.Now(), "", "race")
		if err != nil {
			t.Fatal(err)
		}
		_, refresh := c.grantFor(t, sess)

		var wg sync.WaitGroup
		begin := make(chan struct{})
		var rotated *mcpauth.TokenResponse
		var revokeErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-begin
			rotated, _ = h.deps.OAuth.Token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, c.clientID, "")
		}()
		go func() {
			defer wg.Done()
			<-begin
			_, revokeErr = h.deps.Identity.RevokeSession(ctx, sess.ID, "race")
		}()
		close(begin)
		wg.Wait()
		if revokeErr != nil {
			t.Fatal(revokeErr)
		}

		if n := liveInFamily(t, h, refresh); n != 0 {
			t.Fatalf("round %d: %d refresh tokens of the ended session are still live", i, n)
		}
		if rotated == nil {
			continue
		}
		if _, err := h.deps.OAuth.PrincipalFromToken(ctx, rotated.AccessToken); err == nil {
			t.Fatalf("round %d: the access token a racing refresh returned is accepted", i)
		}
		if _, err := h.deps.OAuth.Token(ctx, url.Values{"grant_type": {"refresh_token"},
			"refresh_token": {rotated.RefreshToken}}, c.clientID, ""); err == nil {
			t.Fatalf("round %d: the refresh token a racing refresh returned still works", i)
		}
	}
}

// TestTokenOfMissingSessionRefused removes the session a token names, as
// the pruner might, and checks that neither the access token nor the
// refresh token works afterwards. It also checks the pruner keeps a
// session, expired or not, that a live refresh token still names.
func TestTokenOfMissingSessionRefused(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	admin := h.register(t, "E2E OAuth missing session")
	c := newOAuthClient(t, h, admin.Org.ID, admin.User.ID)
	sess, err := h.deps.Identity.CreateSession(ctx, admin.User.ID, admin.Org.ID, "password", "", nil, time.Now(), "", "prune")
	if err != nil {
		t.Fatal(err)
	}
	_, refresh := c.grantFor(t, sess)

	exec := func(q string, args ...any) {
		t.Helper()
		if err := h.db.Bypass(ctx, "e2e session rows", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, q, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Long expired: the pruner would take it, but a live refresh token
	// names it, so it stays, and the token keeps working.
	exec(`UPDATE sessions SET idle_expires_at = now() - interval '30 days',
		absolute_expires_at = now() - interval '30 days' WHERE id = $1`, sess.ID)
	if err := h.deps.Identity.PruneSessions(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := h.deps.OAuth.Token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, c.clientID, "")
	if err != nil {
		t.Fatalf("a refresh token of an expired session was refused: %v", err)
	}
	access := res.AccessToken
	refresh = res.RefreshToken

	exec(`DELETE FROM sessions WHERE id = $1`, sess.ID)
	if _, err := h.deps.OAuth.PrincipalFromToken(ctx, access); err == nil {
		t.Error("an access token naming a session that is not on record is accepted")
	}
	var oe *mcpauth.OAuthError
	if _, err := h.deps.OAuth.Token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}},
		c.clientID, ""); !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Errorf("refresh with the session gone: %v, want invalid_grant", err)
	}
	if n := liveInFamily(t, h, refresh); n != 0 {
		t.Errorf("%d refresh tokens are live after the refusal, want the family revoked", n)
	}
}

// TestSessionEndReachesUnboundChild covers the rolling upgrade: a replica
// of the previous release rotates a session's refresh token into a child
// that names no session. Ending the session still revokes the child,
// because revocation goes by family.
func TestSessionEndReachesUnboundChild(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	admin := h.register(t, "E2E OAuth unbound child")
	c := newOAuthClient(t, h, admin.Org.ID, admin.User.ID)
	sess, err := h.deps.Identity.CreateSession(ctx, admin.User.ID, admin.Org.ID, "password", "", nil, time.Now(), "", "roll")
	if err != nil {
		t.Fatal(err)
	}
	_, refresh := c.grantFor(t, sess)

	// What the previous release's rotation writes: the parent consumed,
	// the child without session_id or amr.
	child := "child-" + newID() + newID()
	parentSum, childSum := sha256.Sum256([]byte(refresh)), sha256.Sum256([]byte(child))
	if err := h.db.Bypass(ctx, "e2e old replica rotation", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE oauth_refresh_tokens SET consumed_at = now() WHERE token_hash = $1`, parentSum[:]); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO oauth_refresh_tokens (id, token_hash, family_id, parent_id, client_id, user_id, organization_id, server_id, scope, expires_at)
			SELECT $2, $3, family_id, id, client_id, user_id, organization_id, server_id, scope, now() + interval '30 days'
			FROM oauth_refresh_tokens WHERE token_hash = $1`, parentSum[:], newID(), childSum[:])
		return err
	}); err != nil {
		t.Fatal(err)
	}

	revoked, err := h.deps.Identity.RevokeSession(ctx, sess.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if revoked != 1 {
		t.Errorf("ending the session reports %d refresh tokens revoked, want the one live child", revoked)
	}
	if n := liveInFamily(t, h, child); n != 0 {
		t.Errorf("the unbound child is still live after its session ended")
	}
	var oe *mcpauth.OAuthError
	if _, err := h.deps.OAuth.Token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {child}},
		c.clientID, ""); !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Errorf("refresh with the unbound child: %v, want invalid_grant", err)
	}
}

// TestIntrospectionStaysInItsWorkspace checks who may introspect a
// token: a key of the token's own workspace may; a key of another
// workspace, or one bound to another server, is told the token is
// inactive, and learns nothing about it.
func TestIntrospectionStaysInItsWorkspace(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	admin := h.register(t, "E2E introspection home")
	c := newOAuthClient(t, h, admin.Org.ID, admin.User.ID)
	access, _ := c.grant(t)

	if in := introspector(t, h, admin.Org.ID, admin.User.ID)(access); !in.Active || in.Sid == "" {
		t.Fatalf("a key of the token's workspace: %+v, want active with a sid", in)
	}

	other := h.anonymous().register(t, "E2E introspection elsewhere")
	if in := introspector(t, h, other.Org.ID, other.User.ID)(access); in.Active || in.Sid != "" || in.Sub != "" || in.AMR != nil {
		t.Errorf("a key of another workspace: %+v, want only active false", in)
	}

	elsewhere, err := h.servers.Create(tenant.WithOrg(ctx, admin.Org.ID), admin.Org.ID, "Elsewhere", "", "", nil, admin.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, bound, err := h.deps.Keys.Create(ctx, mcpauth.CreateInput{OrgID: admin.Org.ID, PrincipalKind: "user",
		PrincipalID: admin.User.ID, Name: "bound elsewhere", ServerID: elsewhere.ID,
		Scopes: []string{"mcp:tools:read"}, CreatedBy: admin.User.ID})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"token": {access}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url+"/oauth/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-API-Key", bound)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var in mcpauth.Introspection
	if err := json.NewDecoder(resp.Body).Decode(&in); err != nil {
		t.Fatal(err)
	}
	if in.Active {
		t.Errorf("a key bound to another server: %+v, want active false", in)
	}
}
