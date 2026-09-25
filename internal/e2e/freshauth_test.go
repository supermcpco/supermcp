package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/identity/sso"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// The password every harness account is registered with.
const e2ePassword = "correct horse battery 9"

// refusal is the body of a huma error, as far as these tests read it.
type refusal struct {
	Status int    `json:"status"`
	Detail string `json:"detail"`
	Errors []struct {
		Location string `json:"location"`
		Value    any    `json:"value"`
	} `json:"errors"`
}

func (r refusal) code() string {
	for _, e := range r.Errors {
		if s, ok := e.Value.(string); ok {
			return s
		}
	}
	return ""
}

// ageSessions moves the authentication time of every session the user
// holds into the past, which is the one thing these tests cannot get the
// product to do by itself.
func (h *harness) ageSessions(t *testing.T, userID string) {
	t.Helper()
	ctx := context.Background()
	if err := h.db.Bypass(ctx, "e2e age sessions", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sessions SET authenticated_at = now() - interval '10 minutes' WHERE user_id = $1`, userID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) createKey(t *testing.T, name string, scopes []string) (int, refusal, string) {
	t.Helper()
	body := map[string]any{"name": name}
	if scopes != nil {
		body["scopes"] = scopes
	}
	var raw json.RawMessage
	code := h.do(t, http.MethodPost, "/api/v1/api-keys", body, &raw)
	var ref refusal
	var created struct {
		Secret string `json:"secret"`
	}
	if code == http.StatusOK {
		_ = json.Unmarshal(raw, &created)
	} else {
		_ = json.Unmarshal(raw, &ref)
	}
	return code, ref, created.Secret
}

// asKey sends a request authenticated by an API key and nothing else.
func (h *harness) asKey(t *testing.T, key, method, path string, body any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(t.Context(), method, h.url+path, strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func (h *harness) clearLockouts(t *testing.T, email string) {
	t.Helper()
	ctx := context.Background()
	clear := func() error {
		return h.db.Bypass(ctx, "e2e lockouts", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM login_lockouts WHERE key = $1 OR key = 'ip:127.0.0.1'`, "user:"+email)
			return err
		})
	}
	if err := clear(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clear() })
}

// TestFreshAuthGuardsSensitiveOperations drives the whole contract for a
// password session: fresh passes, stale is refused with the code a client
// acts on and an audit record, an API key is not held to it, and
// confirming the password makes the same session fresh again.
func TestFreshAuthGuardsSensitiveOperations(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	admin := h.register(t, "E2E fresh auth")
	h.clearLockouts(t, admin.User.Email)

	// Signed in a moment ago: fresh.
	code, _, apiKey := h.createKey(t, "while fresh", []string{"mcp:org"})
	if code != http.StatusOK {
		t.Fatalf("a fresh session could not create a key: %d", code)
	}

	var before struct {
		SignIn struct {
			Method          string `json:"method"`
			AuthenticatedAt string `json:"authenticatedAt"`
			FreshUntil      string `json:"freshUntil"`
		} `json:"signIn"`
	}
	if code := h.do(t, http.MethodGet, "/api/v1/auth/session", nil, &before); code != 200 || before.SignIn.Method != "password" {
		t.Fatalf("the session does not say it signed in with a password: %d %+v", code, before)
	}

	h.ageSessions(t, admin.User.ID)
	cookie := h.cookie

	// Stale: refused with the code, on every kind of sensitive operation.
	code, ref, _ := h.createKey(t, "while stale", nil)
	if code != http.StatusForbidden || ref.code() != "reauth_required" || !strings.HasPrefix(ref.Detail, "reauth_required:") {
		t.Fatalf("a stale session creating a key: %d %+v, want 403 reauth_required", code, ref)
	}
	// The check comes before the lookup, so ids that name nothing are
	// enough to show each one is guarded.
	for _, c := range []struct{ method, path string }{
		{http.MethodDelete, "/api/v1/api-keys/none"},
		{http.MethodPost, "/api/v1/api-keys/none/rotate"},
		{http.MethodDelete, "/api/v1/roles/none"},
		{http.MethodDelete, "/api/v1/roles/role_viewer/bindings/none"},
		{http.MethodDelete, "/api/v1/org/members/none"},
		{http.MethodDelete, "/api/v1/service-accounts/none"},
		{http.MethodPost, "/api/v1/service-accounts/none/rotate"},
		{http.MethodDelete, "/api/v1/idps/none"},
		{http.MethodDelete, "/api/v1/dlp/policies/none"},
		{http.MethodDelete, "/api/v1/approval-policies/none"},
		{http.MethodDelete, "/api/v1/audit/exporters/none"},
		{http.MethodPost, "/api/v1/connectors/none/oauth/authorize"},
		{http.MethodPost, "/api/v1/approvals/none/approve"},
		{http.MethodPut, "/api/v1/connectors/none/credentials"},
	} {
		var r refusal
		var body any
		switch c.method {
		case http.MethodPost:
			body = map[string]any{}
		case http.MethodPut:
			body = map[string]any{"credentials": map[string]string{}}
		}
		if code := h.do(t, c.method, c.path, body, &r); code != http.StatusForbidden || r.code() != "reauth_required" {
			t.Errorf("%s %s from a stale session: %d %+v, want 403 reauth_required", c.method, c.path, code, r)
		}
	}
	// Reading is not guarded, and the session itself still works.
	if code := h.do(t, http.MethodGet, "/api/v1/api-keys", nil, nil); code != http.StatusOK {
		t.Fatalf("a stale session could not list keys: %d", code)
	}

	// The refusal is on the audit trail, with its reason.
	var denied *audit.Record
	events := h.auditEvents(t, ctx, admin.Org.ID)
	for i, e := range events {
		if e.Action == "access.denied" && e.Outcome == audit.Denied {
			if e.Meta["reason"] == "reauth_required" {
				denied = &events[i]
				break
			}
		}
	}
	if denied == nil {
		t.Fatalf("the refusal is not on the audit trail; it holds %v", actions(events))
	}

	// An API key cannot re-authenticate and is not asked to.
	if code := h.asKey(t, apiKey, http.MethodPost, "/api/v1/api-keys", map[string]any{"name": "by key"}); code != http.StatusOK {
		t.Fatalf("an API key creating a key: %d, want 200", code)
	}

	// A wrong password is refused without ending the session, and counts
	// toward the sign-in lockout.
	var wrong refusal
	if code := h.do(t, http.MethodPost, "/api/v1/auth/reauth", map[string]any{"password": "not the password"}, &wrong); code != http.StatusBadRequest {
		t.Fatalf("a wrong password: %d %+v, want 400", code, wrong)
	}
	if failures := lockoutFailures(t, h, "user:"+admin.User.Email); failures != 1 {
		t.Fatalf("a wrong password left %d failures on the account, want 1", failures)
	}
	if code, _, _ := h.createKey(t, "after a wrong password", nil); code != http.StatusForbidden {
		t.Fatalf("a wrong password made the session fresh: %d", code)
	}

	// The right one makes this same session fresh again.
	var ok struct {
		AuthenticatedAt string `json:"authenticatedAt"`
		FreshUntil      string `json:"freshUntil"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/auth/reauth", map[string]any{"password": e2ePassword}, &ok); code != http.StatusOK {
		t.Fatalf("re-authenticating: %d", code)
	}
	if h.cookie != cookie {
		t.Fatal("re-authenticating replaced the session cookie; it should move the clock on the same session")
	}
	if ok.AuthenticatedAt <= before.SignIn.AuthenticatedAt || ok.FreshUntil == "" {
		t.Fatalf("re-authenticating did not move the clock: %+v, signed in at %s", ok, before.SignIn.AuthenticatedAt)
	}
	if failures := lockoutFailures(t, h, "user:"+admin.User.Email); failures != 0 {
		t.Fatalf("a successful re-authentication left %d failures, want them cleared as a sign-in does", failures)
	}
	if code, _, _ := h.createKey(t, "after re-authenticating", nil); code != http.StatusOK {
		t.Fatalf("a re-authenticated session creating a key: %d", code)
	}
}

// TestFreshAuthGuardsServerReach shows that what widens the reach of a
// server-bound key asks for a recent sign-in: creating a server, changing
// which connectors a server serves or turning it on, and putting a server
// or a connector back the way a revision found it. A rename does not.
func TestFreshAuthGuardsServerReach(t *testing.T) {
	h := start(t)
	admin := h.register(t, "E2E fresh auth servers")
	h.clearLockouts(t, admin.User.Email)

	var srv struct {
		ID string `json:"id"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/servers", map[string]any{"name": "while fresh"}, &srv); code != http.StatusOK {
		t.Fatalf("a fresh session creating a server: %d", code)
	}
	h.ageSessions(t, admin.User.ID)

	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/v1/servers", map[string]any{"name": "while stale"}},
		{http.MethodPatch, "/api/v1/servers/" + srv.ID, map[string]any{"connectorIds": []string{}}},
		{http.MethodPatch, "/api/v1/servers/" + srv.ID, map[string]any{"enabled": true}},
		// The check comes before the snapshot is read, so a revision
		// that does not exist is enough.
		{http.MethodPost, "/api/v1/servers/" + srv.ID + "/revisions/99/restore", nil},
		{http.MethodPost, "/api/v1/connectors/none/revisions/99/restore", nil},
	} {
		var r refusal
		if code := h.do(t, c.method, c.path, c.body, &r); code != http.StatusForbidden || r.code() != "reauth_required" {
			t.Errorf("%s %s %v from a stale session: %d %+v, want 403 reauth_required", c.method, c.path, c.body, code, r)
		}
	}
	// A rename or turning a server off narrows nothing's reach.
	if code := h.do(t, http.MethodPatch, "/api/v1/servers/"+srv.ID, map[string]any{"name": "renamed", "enabled": false}, nil); code != http.StatusOK {
		t.Fatalf("a stale session renaming a server: %d, want 200", code)
	}

	if code := h.do(t, http.MethodPost, "/api/v1/auth/reauth", map[string]any{"password": e2ePassword}, nil); code != http.StatusOK {
		t.Fatalf("re-authenticating: %d", code)
	}
	if code := h.do(t, http.MethodPatch, "/api/v1/servers/"+srv.ID, map[string]any{"connectorIds": []string{}, "enabled": true}, nil); code != http.StatusOK {
		t.Fatalf("a re-authenticated session changing a server's connectors: %d", code)
	}
}

// TestReauthLockout shows the prompt is no easier to guess a password
// through than the sign-in form: enough wrong answers lock the account,
// and then even the right one is refused.
func TestReauthLockout(t *testing.T) {
	h := start(t)
	admin := h.register(t, "E2E reauth lockout")
	h.clearLockouts(t, admin.User.Email)
	threshold := h.deps.Identity.Cfg.LockoutThreshold
	for i := 0; i < threshold; i++ {
		if code := h.do(t, http.MethodPost, "/api/v1/auth/reauth", map[string]any{"password": "wrong"}, nil); code != http.StatusBadRequest {
			t.Fatalf("attempt %d: %d, want 400", i, code)
		}
	}
	if code := h.do(t, http.MethodPost, "/api/v1/auth/reauth", map[string]any{"password": e2ePassword}, nil); code != http.StatusTooManyRequests {
		t.Fatalf("the right password after %d wrong ones: %d, want 429", threshold, code)
	}
	// The same counter guards the sign-in form.
	anon := h.anonymous()
	if code := anon.do(t, http.MethodPost, "/api/v1/auth/login",
		map[string]any{"email": admin.User.Email, "password": e2ePassword}, nil); code != http.StatusTooManyRequests {
		t.Fatalf("signing in after the prompt locked the account: %d, want 429", code)
	}
}

func lockoutFailures(t *testing.T, h *harness, key string) int {
	t.Helper()
	ctx := context.Background()
	var n int
	if err := h.db.Bypass(ctx, "e2e lockout count", func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT failures FROM login_lockouts WHERE key = $1`, key).Scan(&n)
		if errors.Is(err, pgx.ErrNoRows) {
			n = 0
			return nil
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// ssoBrowser is one browser signing in through a fake provider.
type ssoBrowser struct {
	h      *harness
	idp    *fakeIdP
	prov   *sso.Provider
	jar    *cookiejar.Jar
	client *http.Client
}

func newSSOBrowser(t *testing.T, h *harness, orgName string) (*ssoBrowser, registered) {
	t.Helper()
	idp := newFakeIdP(t)
	idp.email = newID() + "@example.test"
	idp.subject = "sub-" + newID()
	admin := h.register(t, orgName)
	octx := tenant.WithOrg(context.Background(), admin.Org.ID)
	prov, err := h.deps.SSO.Create(octx, admin.Org.ID, admin.User.ID, sso.Input{
		Name: "Reauth IdP", Preset: "generic", Issuer: idp.URL, ClientID: idp.clientID,
		ClientSecret: "test-secret", JITProvisioning: true, DefaultRoleID: "role_admin", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &ssoBrowser{h: h, idp: idp, prov: prov, jar: jar, client: &http.Client{Jar: jar}}, admin
}

// follow walks a redirect chain and returns where it ended.
func (b *ssoBrowser) follow(t *testing.T, path string) *url.URL {
	t.Helper()
	resp, err := b.client.Get(b.h.url + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Request.URL
}

// session is a harness carrying whatever session cookie the browser holds.
func (b *ssoBrowser) session() *harness {
	base, _ := url.Parse(b.h.url)
	parts := []string{}
	for _, c := range b.jar.Cookies(base) {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return &harness{url: b.h.url, client: b.h.client, deps: b.h.deps, db: b.h.db, cookie: strings.Join(parts, "; ")}
}

type ssoSignInView struct {
	User   struct{ ID string } `json:"user"`
	SignIn struct {
		Method       string `json:"method"`
		ProviderID   string `json:"providerId"`
		ProviderName string `json:"providerName"`
		ReauthURL    string `json:"reauthUrl"`
		CanReauth    bool   `json:"canReauth"`
	} `json:"signIn"`
}

func (h *harness) replacedCount(t *testing.T, userID string) int {
	t.Helper()
	ctx := context.Background()
	var n int
	if err := h.db.Bypass(ctx, "e2e revoked", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_reason = 'replaced by re-authentication'`,
			userID).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestSSOReauth re-authenticates a single sign-on session through its
// provider. The provider is asked to sign the person in again, and the
// answer is judged by the auth_time it carries, not by having asked: an
// auth_time older than the window, or none at all, leaves the stale
// session as it was; a recent one opens a fresh session and ends the old.
func TestSSOReauth(t *testing.T) {
	h := start(t)
	b, _ := newSSOBrowser(t, h, "E2E SSO reauth")
	now := func() int64 { return time.Now().Unix() }
	b.idp.authTime = now

	if end := b.follow(t, "/auth/sso/"+b.prov.ID+"/start?next=/connectors"); end.Path != "/connectors" {
		t.Fatalf("the sign-in ended at %s", end)
	}
	if b.idp.prompt != "" || b.idp.maxAge != "" {
		t.Fatalf("an ordinary sign-in asked the provider for prompt=%q max_age=%q", b.idp.prompt, b.idp.maxAge)
	}
	first := b.session()
	var sess ssoSignInView
	if code := first.do(t, http.MethodGet, "/api/v1/auth/session", nil, &sess); code != 200 {
		t.Fatalf("session: %d", code)
	}
	if sess.SignIn.Method != "sso" || sess.SignIn.ProviderID != b.prov.ID || sess.SignIn.ProviderName != "Reauth IdP" ||
		!sess.SignIn.CanReauth || !strings.Contains(sess.SignIn.ReauthURL, "reauth=1") {
		t.Fatalf("the session does not say how to sign in again: %+v", sess.SignIn)
	}
	if code, _, _ := first.createKey(t, "sso fresh", nil); code != http.StatusOK {
		t.Fatalf("a session the provider said authenticated just now, creating a key: %d", code)
	}

	// Stale, and a password is not accepted in place of the provider.
	h.ageSessions(t, sess.User.ID)
	if code, ref, _ := first.createKey(t, "sso stale", nil); code != http.StatusForbidden || ref.code() != "reauth_required" {
		t.Fatalf("a stale SSO session creating a key: %d %+v", code, ref)
	}
	if code := first.do(t, http.MethodPost, "/api/v1/auth/reauth", map[string]any{"password": "anything"}, nil); code != http.StatusConflict {
		t.Fatalf("a password re-authentication of an SSO session: %d, want 409", code)
	}
	// Setting a password from a stale SSO session would be a way in that
	// outlives the session.
	var pw refusal
	if code := first.do(t, http.MethodPost, "/api/v1/auth/password", map[string]any{"newPassword": "Another Horse Battery 7"}, &pw); code != http.StatusForbidden || pw.code() != "reauth_required" {
		t.Fatalf("setting a password from a stale SSO session: %d %+v", code, pw)
	}

	// An ordinary sign-in from the same browser is not a re-authentication
	// and ends nothing.
	b.follow(t, "/auth/sso/"+b.prov.ID+"/start?next=/connectors")
	if n := h.replacedCount(t, sess.User.ID); n != 0 {
		t.Fatalf("an ordinary sign-in ended %d sessions as replaced", n)
	}
	h.ageSessions(t, sess.User.ID)
	stale := b.session()

	refused := func(name, reason string) {
		t.Helper()
		end := b.follow(t, sess.SignIn.ReauthURL+"&next=/connectors")
		if b.idp.prompt != "login" || b.idp.maxAge != "0" {
			t.Fatalf("%s: the re-authentication asked for prompt=%q max_age=%q, want login and 0", name, b.idp.prompt, b.idp.maxAge)
		}
		if end.Path != "/reauth" || end.Query().Get("error") != reason || end.Query().Get("next") != "/connectors" {
			t.Fatalf("%s: ended at %s, want /reauth with error=%s", name, end, reason)
		}
		now := b.session()
		if now.cookie != stale.cookie {
			t.Fatalf("%s: a refused re-authentication changed the session cookie", name)
		}
		if code, _, _ := now.createKey(t, name, nil); code != http.StatusForbidden {
			t.Fatalf("%s: the session became fresh: %d", name, code)
		}
		if code := now.do(t, http.MethodGet, "/api/v1/api-keys", nil, nil); code != http.StatusOK {
			t.Fatalf("%s: the session stopped working: %d", name, code)
		}
		if n := h.replacedCount(t, sess.User.ID); n != 0 {
			t.Fatalf("%s: %d sessions were ended as replaced", name, n)
		}
	}
	// The provider answered from a sign-in older than the window.
	b.idp.authTime = func() int64 { return time.Now().Add(-10 * time.Minute).Unix() }
	refused("auth_time too old", "reauth_not_recent")
	// The provider did not say when.
	b.idp.authTime = nil
	refused("no auth_time", "reauth_unconfirmed")

	// A recent auth_time: a new, fresh session, and the old one ends.
	b.idp.authTime = now
	if end := b.follow(t, sess.SignIn.ReauthURL+"&next=/connectors"); end.Path != "/connectors" {
		t.Fatalf("the re-authentication ended at %s", end)
	}
	second := b.session()
	if second.cookie == stale.cookie {
		t.Fatal("the re-authentication did not open a new session")
	}
	if code, _, _ := second.createKey(t, "sso reauthenticated", nil); code != http.StatusOK {
		t.Fatalf("the re-authenticated session creating a key: %d", code)
	}
	if code := stale.do(t, http.MethodGet, "/api/v1/api-keys", nil, nil); code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Fatalf("the replaced session still works: %d", code)
	}
	if n := h.replacedCount(t, sess.User.ID); n != 1 {
		t.Fatalf("%d sessions were ended as replaced, want 1", n)
	}
}

// TestSSOReauthRefusesAnotherPerson starts a re-authentication from one
// person's session and has the provider answer for somebody else. No
// session opens for the other person, and the first one stays live.
func TestSSOReauthRefusesAnotherPerson(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	b, admin := newSSOBrowser(t, h, "E2E SSO reauth mismatch")
	b.idp.authTime = func() int64 { return time.Now().Unix() }
	b.follow(t, "/auth/sso/"+b.prov.ID+"/start?next=/connectors")
	first := b.session()
	var sess ssoSignInView
	if code := first.do(t, http.MethodGet, "/api/v1/auth/session", nil, &sess); code != 200 {
		t.Fatalf("session: %d", code)
	}
	h.ageSessions(t, sess.User.ID)

	// The provider now answers for a different person.
	other := newID() + "@example.test"
	b.idp.email, b.idp.subject = other, "sub-"+newID()
	end := b.follow(t, sess.SignIn.ReauthURL+"&next=/connectors")
	if end.Path != "/reauth" || end.Query().Get("error") != "reauth_mismatch" {
		t.Fatalf("a re-authentication answered for another person ended at %s", end)
	}
	if b.session().cookie != first.cookie {
		t.Fatal("a session was opened for the other person")
	}
	if code := first.do(t, http.MethodGet, "/api/v1/api-keys", nil, nil); code != http.StatusOK {
		t.Fatalf("the original session stopped working: %d", code)
	}
	var sessions int
	if err := h.db.Bypass(ctx, "e2e other sessions", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.email = $1`,
			other).Scan(&sessions)
	}); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("%d sessions were opened for the other person", sessions)
	}
	// The refusal is on the audit trail.
	found := false
	for _, e := range h.auditEvents(t, ctx, admin.Org.ID) {
		if e.Action == "session.reauth" && e.Outcome == audit.Failure && e.Meta["reason"] == "reauth_mismatch" {
			found = true
		}
	}
	if !found {
		t.Fatal("the refused re-authentication is not on the audit trail")
	}
}

// TestOAuthConsentNeedsRecentSignIn covers the consent page, which is
// served by the server rather than the interface: granting a client a
// token needs a recent sign-in, authorize sends a stale session to the
// interface's /reauth page and back, and a consent form left open past
// the window is refused when it is submitted.
func TestOAuthConsentNeedsRecentSignIn(t *testing.T) {
	h := start(t)
	upstream, _ := fakeUpstream(t)
	ctx := context.Background()
	admin := h.register(t, "E2E OAuth fresh")
	octx := tenant.WithOrg(ctx, admin.Org.ID)
	c, err := h.connectors.Create(octx, admin.Org.ID, testConnector(t, upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := h.servers.Create(octx, admin.Org.ID, "OAuth fresh server", "", "", []string{c.ID}, admin.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	var client struct {
		ClientID string `json:"client_id"`
	}
	if code := h.do(t, http.MethodPost, "/oauth/register", map[string]any{
		"client_name": "Fresh Client", "redirect_uris": []string{"http://127.0.0.1:7777/callback"},
	}, &client); code != 201 {
		t.Fatalf("register client: %d", code)
	}
	sum := sha256.Sum256([]byte("fresh-verifier-" + newID() + newID()))
	q := url.Values{"response_type": {"code"}, "client_id": {client.ClientID},
		"redirect_uri": {"http://127.0.0.1:7777/callback"}, "state": {"xyz"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"scope": {"mcp:tools:read"}, "resource": {h.url + "/mcp/" + srv.ID}}
	noRedirect := *h.client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	send := func(method, path string, form url.Values) *http.Response {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, _ := http.NewRequestWithContext(ctx, method, h.url+path, body)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		req.Header.Set("Cookie", h.cookie)
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	// Fresh: the consent page, whose form is then left open too long.
	page := h.getString(t, "/oauth/authorize?"+q.Encode())
	id := between(page, `name="request_id" value="`, `"`)
	if id == "" {
		t.Fatalf("no consent page for a fresh session: %s", page)
	}
	h.ageSessions(t, admin.User.ID)
	if resp := send(http.MethodPost, "/oauth/consent", url.Values{"request_id": {id}, "decision": {"allow"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("granting from a stale session: %d, want 403", resp.StatusCode)
	}

	// Stale: authorize sends the person to confirm who they are, and back.
	resp := send(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Path != "/reauth" || !strings.HasPrefix(loc.Query().Get("next"), "/oauth/authorize?") {
		t.Fatalf("authorize from a stale session: %d %s, want a redirect to /reauth", resp.StatusCode, loc)
	}
	if code := h.do(t, http.MethodPost, "/api/v1/auth/reauth", map[string]any{"password": e2ePassword}, nil); code != http.StatusOK {
		t.Fatalf("re-authenticating: %d", code)
	}
	page = h.getString(t, loc.Query().Get("next"))
	id = between(page, `name="request_id" value="`, `"`)
	if id == "" {
		t.Fatalf("no consent page after re-authenticating: %s", page)
	}
	resp = send(http.MethodPost, "/oauth/consent", url.Values{"request_id": {id}, "decision": {"allow"}})
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "http://127.0.0.1:7777/callback") {
		t.Fatalf("granting after re-authenticating: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}
