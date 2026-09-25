package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

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
	} {
		var r refusal
		var body any
		if c.method == http.MethodPost {
			body = map[string]any{}
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

// TestSSOReauth re-authenticates a single sign-on session through its
// provider: the provider is asked to sign the person in again, a new
// session opens, and the one it replaces is ended.
func TestSSOReauth(t *testing.T) {
	h := start(t)
	idp := newFakeIdP(t)
	idp.email = newID() + "@example.test"
	idp.subject = "sub-" + newID()
	ctx := context.Background()

	admin := h.register(t, "E2E SSO reauth")
	octx := tenant.WithOrg(ctx, admin.Org.ID)
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
	client := &http.Client{Jar: jar}
	base, _ := url.Parse(h.url)
	signedIn := func() *harness {
		parts := []string{}
		for _, c := range jar.Cookies(base) {
			parts = append(parts, c.Name+"="+c.Value)
		}
		return &harness{url: h.url, client: h.client, deps: h.deps, db: h.db, cookie: strings.Join(parts, "; ")}
	}
	follow := func(path string) {
		t.Helper()
		resp, err := client.Get(h.url + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.Request.URL.Path != "/connectors" {
			t.Fatalf("the sign-in ended at %s", resp.Request.URL)
		}
	}
	follow("/auth/sso/" + prov.ID + "/start?next=/connectors")
	if idp.prompt != "" {
		t.Fatalf("an ordinary sign-in asked the provider for prompt=%q", idp.prompt)
	}
	first := signedIn()

	var sess struct {
		User   struct{ ID string } `json:"user"`
		SignIn struct {
			Method       string `json:"method"`
			ProviderID   string `json:"providerId"`
			ProviderName string `json:"providerName"`
			ReauthURL    string `json:"reauthUrl"`
		} `json:"signIn"`
	}
	if code := first.do(t, http.MethodGet, "/api/v1/auth/session", nil, &sess); code != 200 {
		t.Fatalf("session: %d", code)
	}
	if sess.SignIn.Method != "sso" || sess.SignIn.ProviderID != prov.ID || sess.SignIn.ProviderName != "Reauth IdP" ||
		!strings.Contains(sess.SignIn.ReauthURL, "reauth=1") {
		t.Fatalf("the session does not say how to sign in again: %+v", sess.SignIn)
	}
	if code, _, _ := first.createKey(t, "sso fresh", nil); code != http.StatusOK {
		t.Fatalf("a fresh SSO session creating a key: %d", code)
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

	follow(sess.SignIn.ReauthURL + "&next=/connectors")
	if idp.prompt != "login" {
		t.Fatalf("the re-authentication asked the provider for prompt=%q, want login", idp.prompt)
	}
	second := signedIn()
	if second.cookie == first.cookie {
		t.Fatal("the re-authentication did not open a new session")
	}
	if code, _, _ := second.createKey(t, "sso reauthenticated", nil); code != http.StatusOK {
		t.Fatalf("the re-authenticated session creating a key: %d", code)
	}
	// The session it replaced is over.
	if code := first.do(t, http.MethodGet, "/api/v1/api-keys", nil, nil); code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Fatalf("the replaced session still works: %d", code)
	}
	var revoked int
	if err := h.db.Bypass(ctx, "e2e revoked", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_reason = 'replaced by re-authentication'`,
			sess.User.ID).Scan(&revoked)
	}); err != nil {
		t.Fatal(err)
	}
	if revoked != 1 {
		t.Fatalf("%d sessions were ended as replaced, want 1", revoked)
	}
}
