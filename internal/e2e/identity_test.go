package e2e

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/identity/sso"
	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// fakeIdP is an OpenID Connect provider in about as few moving parts as
// the protocol allows: discovery, an authorization endpoint that redirects
// straight back, a token endpoint, and a key set.
type fakeIdP struct {
	*httptest.Server
	key      *rsa.PrivateKey
	clientID string
	subject  string
	email    string
	groups   []string
	nonce    string
	// prompt is the prompt parameter of the last authorization request.
	prompt string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, clientID: "test-client", subject: "sub-123", email: "sso-user@example.test",
		groups: []string{"engineering"}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                 f.URL,
			"authorization_endpoint": f.URL + "/authorize",
			"token_endpoint":         f.URL + "/token",
			"userinfo_endpoint":      f.URL + "/userinfo",
			"jwks_uri":               f.URL + "/jwks",
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.nonce = q.Get("nonce")
		f.prompt = q.Get("prompt")
		back, _ := url.Parse(q.Get("redirect_uri"))
		rq := back.Query()
		rq.Set("code", "test-code")
		rq.Set("state", q.Get("state"))
		back.RawQuery = rq.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("code") != "test-code" {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "invalid_grant"})
			return
		}
		writeJSON(w, map[string]any{
			"access_token": "test-access-token", "token_type": "Bearer",
			"id_token": f.idToken(t),
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := f.key.Public().(*rsa.PublicKey)
		writeJSON(w, map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// idToken signs the claims the provider would assert about the person.
func (f *fakeIdP) idToken(t *testing.T) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "test-key"}
	claims := map[string]any{
		"iss": f.URL, "sub": f.subject, "aud": f.clientID, "email": f.email,
		"email_verified": true, "name": "SSO User", "groups": f.groups, "nonce": f.nonce,
		"iat": nowUnix(), "exp": nowUnix() + 300,
	}
	seg := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := seg(header) + "." + seg(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestSSOSignIn configures a provider, signs in through it, and checks
// that the group the provider asserted became a role binding.
func TestSSOSignIn(t *testing.T) {
	h := start(t)
	idp := newFakeIdP(t)
	ctx := context.Background()

	admin := h.register(t, "E2E SSO")
	octx := tenant.WithOrg(ctx, admin.Org.ID)

	prov, err := h.deps.SSO.Create(octx, admin.Org.ID, admin.User.ID, sso.Input{
		Name: "Test IdP", Preset: "generic", Issuer: idp.URL, ClientID: idp.clientID,
		ClientSecret: "test-secret", JITProvisioning: true, GroupsClaim: "groups", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// A group the provider asserts is granted the viewer role here.
	if err := h.db.Tx(octx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id)
			VALUES ($1,$2,'idp_group','engineering','role_viewer')`, newID(), admin.Org.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// The sign-in page offers the provider without anyone being signed in.
	var listing struct {
		Providers []struct{ ID, Name string } `json:"providers"`
	}
	anon := &harness{url: h.url, client: h.client, deps: h.deps, db: h.db}
	if code := anon.do(t, http.MethodGet, "/api/v1/auth/sso-providers", nil, &listing); code != 200 {
		t.Fatalf("list providers: %d", code)
	}
	if len(listing.Providers) == 0 {
		t.Fatal("the sign-in page was offered no providers")
	}

	// Follow the whole redirect chain: start, provider, callback.
	jar := &cookieJar{}
	client := &http.Client{Jar: jar}
	resp, err := client.Get(h.url + "/auth/sso/" + prov.ID + "/start?next=/connectors")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Request.URL.Path != "/connectors" {
		t.Fatalf("sign-in ended at %s, not the page it started from", resp.Request.URL)
	}
	if len(jar.cookies) == 0 {
		t.Fatal("the sign-in set no session cookie")
	}

	// The session belongs to the person the provider named.
	var session struct {
		User struct{ Email string } `json:"user"`
		Org  struct{ ID string }    `json:"organization"`
	}
	signed := &harness{url: h.url, client: h.client, deps: h.deps, db: h.db, cookie: jar.header()}
	if code := signed.do(t, http.MethodGet, "/api/v1/auth/session", nil, &session); code != 200 {
		t.Fatalf("session: %d", code)
	}
	if session.User.Email != idp.email {
		t.Fatalf("signed in as %q, expected %q", session.User.Email, idp.email)
	}
	if session.Org.ID != admin.Org.ID {
		t.Fatalf("signed in to %q, expected %q", session.Org.ID, admin.Org.ID)
	}

	// The asserted group became a binding, sourced from the provider.
	var roles []string
	if err := h.db.Tx(octx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT rb.role_id FROM role_bindings rb JOIN users u ON u.id = rb.principal_id
			WHERE rb.organization_id = $1 AND rb.principal_kind = 'user' AND rb.source = 'sso' AND u.email = $2`,
			admin.Org.ID, idp.email)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r string
			if err := rows.Scan(&r); err != nil {
				return err
			}
			roles = append(roles, r)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0] != "role_viewer" {
		t.Fatalf("the provider's group granted %v, expected [role_viewer]", roles)
	}

	// A second sign-in reuses the same account rather than making another.
	resp2, err := client.Get(h.url + "/auth/sso/" + prov.ID + "/start")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var count int
	if err := h.db.Bypass(ctx, "test count", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE email = $1`, idp.email).Scan(&count)
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("signing in twice produced %d accounts", count)
	}
}

// TestSSORefusesForeignDomain checks the allowed-domain rule, which is
// what stops a shared provider from admitting anyone who has an account
// with it.
func TestSSORefusesForeignDomain(t *testing.T) {
	h := start(t)
	idp := newFakeIdP(t)
	ctx := context.Background()
	admin := h.register(t, "E2E SSO domains")
	octx := tenant.WithOrg(ctx, admin.Org.ID)

	prov, err := h.deps.SSO.Create(octx, admin.Org.ID, admin.User.ID, sso.Input{
		Name: "Restricted", Preset: "generic", Issuer: idp.URL, ClientID: idp.clientID,
		ClientSecret: "test-secret", JITProvisioning: true, Enabled: true,
		AllowedDomains: []string{"allowed.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	jar := &cookieJar{}
	client := &http.Client{Jar: jar}
	resp, err := client.Get(h.url + "/auth/sso/" + prov.ID + "/start")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !strings.Contains(resp.Request.URL.String(), "domain_not_allowed") {
		t.Fatalf("a foreign domain was not refused; ended at %s", resp.Request.URL)
	}
	// The flow cookie that carried the sign-in is cleared on the way out,
	// which is a Set-Cookie of its own; what must not be there is a
	// session.
	for _, c := range jar.cookies {
		if strings.Contains(c.Name, "sess") && c.Value != "" {
			t.Fatalf("a refused sign-in still set a session cookie (%s)", c.Name)
		}
	}
}

// TestSCIMProvisioning creates a user through SCIM, puts them in a group,
// then deactivates them and checks that their credentials went with it.
func TestSCIMProvisioning(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	admin := h.register(t, "E2E SCIM")

	// The provisioning system holds a key scoped to SCIM and nothing else.
	var key struct {
		Secret string `json:"secret"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/api-keys", map[string]any{
		"name": "SCIM", "scopes": []string{"scim:write"},
	}, &key); code != 200 && code != 201 {
		t.Fatalf("create key: %d", code)
	}

	scim := func(method, path string, body any, out any) int {
		t.Helper()
		var r *strings.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = strings.NewReader(string(b))
		}
		var req *http.Request
		var err error
		if r != nil {
			req, err = http.NewRequest(method, h.url+path, r)
		} else {
			req, err = http.NewRequest(method, h.url+path, nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/scim+json")
		req.Header.Set("X-API-Key", key.Secret)
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if out != nil {
			_ = json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}

	var created struct {
		ID     string `json:"id"`
		Active *bool  `json:"active"`
	}
	email := newID() + "@scim.test"
	if code := scim(http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   email,
		"externalId": "ext-1",
		"name":       map[string]any{"givenName": "Provisioned", "familyName": "Person"},
		"emails":     []any{map[string]any{"value": email, "primary": true}},
	}, &created); code != http.StatusCreated {
		t.Fatalf("create user: %d", code)
	}
	if created.ID == "" || created.Active == nil || !*created.Active {
		t.Fatalf("the provisioned user came back as %+v", created)
	}

	// The same key reaches nothing outside provisioning.
	req, _ := http.NewRequest(http.MethodGet, h.url+"/api/v1/connectors", nil)
	req.Header.Set("X-API-Key", key.Secret)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a provisioning key listed connectors: %d", resp.StatusCode)
	}

	// The provider looks a user up by userName before creating them.
	var found struct {
		TotalResults int `json:"totalResults"`
		Resources    []struct {
			ID string `json:"id"`
		} `json:"Resources"`
	}
	if code := scim(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(`userName eq "`+email+`"`), nil, &found); code != 200 {
		t.Fatalf("filter users: %d", code)
	}
	if found.TotalResults != 1 || found.Resources[0].ID != created.ID {
		t.Fatalf("the filter found %+v", found)
	}

	// Groups carry membership, which is what role bindings key on.
	var group struct {
		ID      string `json:"id"`
		Members []struct {
			Value string `json:"value"`
		} `json:"members"`
	}
	if code := scim(http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Engineering",
		"members":     []any{map[string]any{"value": created.ID}},
	}, &group); code != http.StatusCreated {
		t.Fatalf("create group: %d", code)
	}
	if len(group.Members) != 1 {
		t.Fatalf("the group was created with %d members", len(group.Members))
	}

	// Give the user a credential, then deactivate them.
	var userKeyID string
	octx := tenant.WithOrg(ctx, admin.Org.ID)
	if err := h.db.Tx(octx, func(tx pgx.Tx) error {
		userKeyID = newID()
		_, err := tx.Exec(ctx, `INSERT INTO api_keys (id, organization_id, principal_kind, principal_id, name, prefix, hash)
			VALUES ($1,$2,'user',$3,'their key',$4,'\x00')`, userKeyID, admin.Org.ID, created.ID, "pfx"+userKeyID[:8])
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if code := scim(http.MethodPatch, "/scim/v2/Users/"+created.ID, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{"op": "replace", "path": "active", "value": false}},
	}, nil); code != 200 {
		t.Fatalf("deactivate: %d", code)
	}

	var revoked bool
	var deactivated bool
	if err := h.db.Tx(octx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM api_keys WHERE id = $1`, userKeyID).Scan(&revoked); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT deactivated_at IS NOT NULL FROM organization_members
			WHERE organization_id = $1 AND user_id = $2`, admin.Org.ID, created.ID).Scan(&deactivated)
	}); err != nil {
		t.Fatal(err)
	}
	if !deactivated {
		t.Error("deactivating the user left their membership active")
	}
	if !revoked {
		t.Error("deactivating the user left their API key usable")
	}
}

// TestSCIMRefusesToolScopedKey checks that a credential minted for calling
// tools cannot provision people.
func TestSCIMRefusesToolScopedKey(t *testing.T) {
	h := start(t)
	h.register(t, "E2E SCIM scope")
	var key struct {
		Secret string `json:"secret"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/api-keys", map[string]any{
		"name": "tools only", "scopes": []string{"mcp:tools:invoke"},
	}, &key); code != 200 && code != 201 {
		t.Fatalf("create key: %d", code)
	}
	req, err := http.NewRequest(http.MethodGet, h.url+"/scim/v2/Users", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", key.Secret)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a tool-scoped key got %d from SCIM, expected 403", resp.StatusCode)
	}
}

// TestServiceAccountToken drives the client credentials grant and checks
// the token carries the account, its organisation and nothing more.
func TestServiceAccountToken(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	admin := h.register(t, "E2E service accounts")

	var created struct {
		ID       string `json:"id"`
		ClientID string `json:"clientId"`
		Secret   string `json:"secret"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/service-accounts", map[string]any{
		"name": "pipeline", "scopes": []string{"mcp:tools:invoke"},
	}, &created); code != http.StatusCreated {
		t.Fatalf("create service account: %d", code)
	}
	if created.Secret == "" {
		t.Fatal("the account was created without a secret")
	}

	token := func(clientID, secret, scope string) (int, map[string]any) {
		form := url.Values{"grant_type": {"client_credentials"}}
		if scope != "" {
			form.Set("scope", scope)
		}
		req, err := http.NewRequest(http.MethodPost, h.url+"/oauth/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, secret)
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body
	}

	code, body := token(created.ClientID, created.Secret, "")
	if code != 200 {
		t.Fatalf("token: %d %v", code, body)
	}
	access, _ := body["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token in %v", body)
	}
	if _, ok := body["refresh_token"]; ok {
		t.Error("a service account was given a refresh token it cannot use")
	}

	p, err := h.deps.OAuth.PrincipalFromToken(ctx, access)
	if err != nil {
		t.Fatal(err)
	}
	if string(p.Kind) != "service_account" || p.ID != created.ID {
		t.Fatalf("the token identifies %s %s, expected the service account", p.Kind, p.ID)
	}
	if p.OrgID != admin.Org.ID {
		t.Fatalf("the token names organisation %s, expected %s", p.OrgID, admin.Org.ID)
	}

	// A wrong secret, and a disabled account, are both refused.
	if code, _ := token(created.ClientID, "not-the-secret", ""); code != http.StatusUnauthorized {
		t.Fatalf("a wrong secret got %d, expected 401", code)
	}
	if code := h.do(t, http.MethodPost, "/api/v1/service-accounts/"+created.ID+"/disabled",
		map[string]any{"disabled": true}, nil); code != 200 {
		t.Fatalf("disable: %d", code)
	}
	if code, _ := token(created.ClientID, created.Secret, ""); code != http.StatusUnauthorized {
		t.Fatalf("a disabled account still got a token")
	}
}

// TestPasswordPolicy checks that the organisation's rules apply to a
// change, and that changing a password ends the other sessions.
func TestPasswordPolicy(t *testing.T) {
	h := start(t)
	h.register(t, "E2E passwords")

	if code := h.do(t, http.MethodPut, "/api/v1/org/password-policy", map[string]any{
		"minLength": 16, "requireClasses": 3, "history": 2, "maxAgeDays": 0,
	}, nil); code != 200 {
		t.Fatalf("set policy: %d", code)
	}

	// Too short for the new policy.
	if code := h.do(t, http.MethodPost, "/api/v1/auth/password", map[string]any{
		"currentPassword": "correct horse battery 9", "newPassword": "short pass 12",
	}, nil); code != http.StatusBadRequest {
		t.Fatalf("a password below the minimum length got %d, expected 400", code)
	}

	// Long enough, and drawing on enough character classes.
	if code := h.do(t, http.MethodPost, "/api/v1/auth/password", map[string]any{
		"currentPassword": "correct horse battery 9", "newPassword": "Stapler Ocean Drift 77",
	}, nil); code != 200 {
		t.Fatalf("a compliant password was refused: %d", code)
	}

	// The old password is now history, and may not come back.
	if code := h.do(t, http.MethodPost, "/api/v1/auth/password", map[string]any{
		"currentPassword": "Stapler Ocean Drift 77", "newPassword": "correct horse battery 9",
	}, nil); code != http.StatusBadRequest {
		t.Fatalf("a recently used password was accepted: %d", code)
	}
}

// TestPasswordMaxAge checks that a password past the workspace's maximum
// age can change itself, read the session and sign out, and do nothing
// else until it is changed.
func TestPasswordMaxAge(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	me := h.register(t, "E2E password age")

	// The password was set at registration and never changed, so it is as
	// old as the account. It is aged before the policy is set: a password
	// found within its age is remembered for a minute, and setting the
	// policy is what forgets that, the way it would after an
	// administrator tightened it.
	if err := h.db.Bypass(ctx, "password age test", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET created_at = now() - interval '31 days' WHERE id = $1`, me.User.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if code := h.do(t, http.MethodPut, "/api/v1/org/password-policy", map[string]any{
		"minLength": 12, "requireClasses": 2, "history": 5, "maxAgeDays": 30,
	}, nil); code != 200 {
		t.Fatalf("set policy: %d", code)
	}

	var sess struct {
		PasswordExpired bool `json:"passwordExpired"`
	}
	if code := h.do(t, http.MethodGet, "/api/v1/auth/session", nil, &sess); code != 200 || !sess.PasswordExpired {
		t.Fatalf("the session does not say the password expired: %d %+v", code, sess)
	}
	for _, path := range []string{"/api/v1/connectors", "/api/v1/api-keys"} {
		if code := h.do(t, http.MethodGet, path, nil, nil); code != http.StatusForbidden {
			t.Errorf("an expired password reached %s: %d", path, code)
		}
	}
	if code := h.do(t, http.MethodPost, "/api/v1/api-keys", map[string]any{"name": "sneak"}, nil); code != http.StatusForbidden {
		t.Errorf("an expired password created an API key: %d", code)
	}

	if code := h.do(t, http.MethodPost, "/api/v1/auth/password", map[string]any{
		"currentPassword": "correct horse battery 9", "newPassword": "Stapler Ocean Drift 77",
	}, nil); code != 200 {
		t.Fatalf("an expired password could not be changed: %d", code)
	}
	if code := h.do(t, http.MethodGet, "/api/v1/connectors", nil, nil); code != 200 {
		t.Fatalf("still refused after the change: %d", code)
	}
	sess.PasswordExpired = false
	if code := h.do(t, http.MethodGet, "/api/v1/auth/session", nil, &sess); code != 200 || sess.PasswordExpired {
		t.Fatalf("the session still says the password expired: %d %+v", code, sess)
	}
}

// --- helpers ---------------------------------------------------------------

type registered struct {
	User struct{ ID, Email string } `json:"user"`
	Org  struct{ ID, Slug string }  `json:"organization"`
}

// register creates an account and leaves the harness signed in as it.
func (h *harness) register(t *testing.T, orgName string) registered {
	t.Helper()
	var out registered
	if code := h.do(t, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email": newID() + "@e2e.test", "password": "correct horse battery 9", "orgName": orgName,
	}, &out); code != 200 {
		t.Fatalf("register: %d", code)
	}
	return out
}

// cookieJar keeps whatever the redirect chain sets, which is the only
// thing this test needs from a jar.
type cookieJar struct{ cookies []*http.Cookie }

func (j *cookieJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	j.cookies = append(j.cookies, cookies...)
}
func (j *cookieJar) Cookies(_ *url.URL) []*http.Cookie { return j.cookies }

func (j *cookieJar) header() string {
	parts := make([]string, 0, len(j.cookies))
	for _, c := range j.cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

func nowUnix() int64 { return time.Now().Unix() }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// TestDCRApproval registers a client under approval mode and walks it
// through the operator's decisions: pending is refused, approved reaches
// consent, and rejected is refused at both ends again.
func TestDCRApproval(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	h.register(t, "E2E DCR")
	h.deps.OAuth.Mode = mcpauth.DCRApproval

	var client struct {
		ClientID string `json:"client_id"`
	}
	if code := h.do(t, http.MethodPost, "/oauth/register", map[string]any{
		"client_name": "Pending Client", "redirect_uris": []string{"http://127.0.0.1:7777/callback"},
	}, &client); code != 201 || client.ClientID == "" {
		t.Fatalf("register client: %d %+v", code, client)
	}
	t.Cleanup(func() {
		_ = h.db.Bypass(ctx, "dcr test cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM oauth_clients WHERE client_id = $1`, client.ClientID)
			return err
		})
	})

	authorize := func() int {
		t.Helper()
		q := url.Values{"response_type": {"code"}, "client_id": {client.ClientID},
			"redirect_uri": {"http://127.0.0.1:7777/callback"}, "state": {"s"},
			"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"},
			"scope": {"mcp:tools:read"}}
		return h.do(t, http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, nil)
	}
	refresh := func() string {
		t.Helper()
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"anything"}, "client_id": {client.ClientID}}
		req, _ := http.NewRequest(http.MethodPost, h.url+"/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out.Error
	}

	if code := authorize(); code != http.StatusForbidden {
		t.Fatalf("a pending client reached authorization: %d", code)
	}
	if e := refresh(); e != "unauthorized_client" {
		t.Fatalf("a pending client reached the token endpoint: %q", e)
	}
	pending, err := h.deps.OAuth.ListClients(ctx, "pending")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(pending, func(c mcpauth.ClientInfo) bool { return c.ClientID == client.ClientID }) {
		t.Fatalf("the new client is not in the pending list: %+v", pending)
	}

	before, _, err := h.deps.OAuth.DecideClient(ctx, client.ClientID, true, "e2e")
	if err != nil || before.Status != "pending" {
		t.Fatalf("approve: %v (was %q)", err, before.Status)
	}
	if code := authorize(); code != http.StatusOK {
		t.Fatalf("an approved client did not reach consent: %d", code)
	}
	// Past the status check, the made-up refresh token is what fails.
	if e := refresh(); e != "invalid_grant" {
		t.Fatalf("an approved client was refused before its token was read: %q", e)
	}

	if _, _, err := h.deps.OAuth.DecideClient(ctx, client.ClientID, false, "e2e"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if code := authorize(); code != http.StatusForbidden {
		t.Fatalf("a rejected client reached authorization: %d", code)
	}
	if e := refresh(); e != "unauthorized_client" {
		t.Fatalf("a rejected client could still refresh: %q", e)
	}
	if _, _, err := h.deps.OAuth.DecideClient(ctx, "smc_never_registered", true, "e2e"); !errors.Is(err, mcpauth.ErrClientNotFound) {
		t.Fatalf("deciding on an unknown client: %v", err)
	}
}
