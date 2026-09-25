package e2e

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/identity/sso"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// sessionMFA reports whether the session the harness's cookie carries has
// a second factor on record, as a policy requiring one reads it.
func sessionMFA(t *testing.T, h, signed *harness) bool {
	t.Helper()
	key, _ := sessionOf(t, signed)
	sess, err := h.deps.Identity.LoadSession(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return h.deps.Identity.Principal(sess, "").MFA
}

// TestOIDCSecondFactor signs in through an OpenID Connect provider with
// different rules and ID tokens, and checks what the session records and
// what an access token consented from it claims. A sign-in counts as
// having a second factor only when the verified ID token meets the
// provider's rule; with no rule, nothing counts.
func TestOIDCSecondFactor(t *testing.T) {
	h := start(t)
	none := &sso.MFARule{}
	okta := &sso.MFARule{ACR: []string{"phr"}}
	tests := []struct {
		name     string
		rule     *sso.MFARule
		amr      []string
		acr      string
		userinfo map[string]any
		wantMFA  bool
		wantAMR  []string
	}{
		{name: "no rule", rule: none, amr: []string{"pwd", "mfa"}, wantMFA: false, wantAMR: []string{"pwd"}},
		{name: "password only", amr: []string{"pwd"}, wantMFA: false, wantAMR: []string{"pwd"}},
		{name: "password and mfa", amr: []string{"pwd", "mfa"}, wantMFA: true, wantAMR: []string{"pwd", "mfa"}},
		{name: "password and otp", amr: []string{"pwd", "otp"}, wantMFA: true, wantAMR: []string{"pwd", "otp", "mfa"}},
		{name: "acr match", rule: okta, amr: []string{"pwd"}, acr: "phr", wantMFA: true, wantAMR: []string{"pwd", "mfa"}},
		{name: "acr not in the rule", rule: okta, amr: []string{"pwd"}, acr: "urn:okta:loa:1fa:pwd", wantMFA: false, wantAMR: []string{"pwd"}},
		// The user endpoint's answer is not signed. The ID token carries no
		// address here, so the user endpoint is asked, and what it says
		// about factors is not read.
		{name: "amr from the user endpoint", userinfo: map[string]any{"amr": []string{"pwd", "mfa"}, "acr": "phr"},
			wantMFA: false, wantAMR: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, admin := newSSOBrowserWithRule(t, h, "E2E OIDC MFA "+tt.name, tt.rule)
			b.idp.authTime = func() int64 { return time.Now().Unix() }
			b.idp.amr, b.idp.acr = tt.amr, tt.acr
			if tt.userinfo != nil {
				b.idp.omitEmail, b.idp.userinfo = true, tt.userinfo
			}
			if end := b.follow(t, "/auth/sso/"+b.prov.ID+"/start?next=/connectors"); end.Path != "/connectors" {
				t.Fatalf("the sign-in ended at %s", end)
			}
			signed := b.session()
			if got := sessionMFA(t, h, signed); got != tt.wantMFA {
				t.Errorf("the session records a second factor: %v, want %v", got, tt.wantMFA)
			}
			c := newOAuthClient(t, h, admin.Org.ID, admin.User.ID)
			c.h = signed
			access, _ := c.grant(t)
			if got := claimAMR(jwtClaims(t, access)); !slices.Equal(got, tt.wantAMR) {
				t.Errorf("the access token's amr = %v, want %v", got, tt.wantAMR)
			}
		})
	}
}

// TestOIDCReauthSecondFactor re-authenticates an OpenID Connect session.
// The replacing session records a second factor only when the new ID
// token meets the rule, so re-authenticating with a password alone
// cannot upgrade a session, and leaves a session that had one without.
func TestOIDCReauthSecondFactor(t *testing.T) {
	h := start(t)
	b, _ := newSSOBrowser(t, h, "E2E OIDC MFA reauth")
	b.idp.authTime = func() int64 { return time.Now().Unix() }
	b.idp.amr = []string{"pwd"}
	if end := b.follow(t, "/auth/sso/"+b.prov.ID+"/start?next=/connectors"); end.Path != "/connectors" {
		t.Fatalf("the sign-in ended at %s", end)
	}
	var sess ssoSignInView
	if code := b.session().do(t, http.MethodGet, "/api/v1/auth/session", nil, &sess); code != http.StatusOK {
		t.Fatalf("session: %d", code)
	}
	if sessionMFA(t, h, b.session()) {
		t.Fatal("a password sign-in recorded a second factor")
	}

	steps := []struct {
		amr  []string
		want bool
	}{
		{[]string{"pwd"}, false},
		{[]string{"pwd", "mfa"}, true},
		{[]string{"pwd"}, false},
	}
	for i, step := range steps {
		before := b.session().cookie
		h.ageSessions(t, sess.User.ID)
		b.idp.amr = step.amr
		if end := b.follow(t, sess.SignIn.ReauthURL+"&next=/connectors"); end.Path != "/connectors" {
			t.Fatalf("re-authentication %d with amr %v ended at %s", i+1, step.amr, end)
		}
		after := b.session()
		if after.cookie == before {
			t.Fatalf("re-authentication %d opened no new session", i+1)
		}
		if got := sessionMFA(t, h, after); got != step.want {
			t.Errorf("after re-authenticating with amr %v the session records a second factor: %v, want %v",
				step.amr, got, step.want)
		}
	}
	if n := h.replacedCount(t, sess.User.ID); n != len(steps) {
		t.Errorf("%d sessions were ended as replaced, want %d", n, len(steps))
	}
}

// TestOIDCSessionFromBeforeTheRule checks a session opened before the
// provider's answer was judged: every OpenID Connect session was marked
// verified then, whatever the provider said, so one without recorded
// methods does not count as having a second factor.
func TestOIDCSessionFromBeforeTheRule(t *testing.T) {
	h := start(t)
	b, _ := newSSOBrowser(t, h, "E2E OIDC MFA legacy")
	b.idp.amr = []string{"pwd", "mfa"}
	if end := b.follow(t, "/auth/sso/"+b.prov.ID+"/start?next=/connectors"); end.Path != "/connectors" {
		t.Fatalf("the sign-in ended at %s", end)
	}
	signed := b.session()
	if !sessionMFA(t, h, signed) {
		t.Fatal("a sign-in that met the rule recorded no second factor")
	}
	key, _ := sessionOf(t, signed)
	ctx := context.Background()
	// What the previous release wrote: verified, and no methods.
	if err := h.db.Bypass(ctx, "e2e legacy session", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sessions SET auth_methods = NULL, mfa_verified_at = now() WHERE id = $1`, key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if sessionMFA(t, h, signed) {
		t.Error("an OpenID Connect session from before the rule counts as having a second factor")
	}
}

// TestIDPSecondFactorRule checks the rule through the API: a new provider
// gets the default, an update that leaves the rule out keeps it, an empty
// rule is no rule, pwd is refused, and GitHub cannot have one.
func TestIDPSecondFactorRule(t *testing.T) {
	h := start(t)
	idp := newFakeIdP(t)
	admin := h.register(t, "E2E IdP rule")
	type provider struct {
		ID  string      `json:"id"`
		MFA sso.MFARule `json:"mfa"`
	}
	body := func(mfa any) map[string]any {
		b := map[string]any{"name": "Rule IdP", "preset": "generic", "issuer": idp.URL, "clientId": idp.clientID,
			"clientSecret": "test-secret", "enabled": true} // gitleaks:allow
		if mfa != nil {
			b["mfa"] = mfa
		}
		return b
	}
	var created provider
	if code := h.do(t, http.MethodPost, "/api/v1/idps", body(nil), &created); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	if want := sso.DefaultMFARule(); !slices.Equal(created.MFA.AMR, want.AMR) || len(created.MFA.ACR) != 0 {
		t.Fatalf("a new provider's rule = %+v, want %+v", created.MFA, want)
	}

	var updated provider
	rule := map[string]any{"amr": []string{"mfa", " hwk ", "mfa"}, "acr": []string{"phr"}}
	if code := h.do(t, http.MethodPut, "/api/v1/idps/"+created.ID, body(rule), &updated); code != http.StatusOK {
		t.Fatalf("update with a rule: %d", code)
	}
	if !slices.Equal(updated.MFA.AMR, []string{"mfa", "hwk"}) || !slices.Equal(updated.MFA.ACR, []string{"phr"}) {
		t.Fatalf("the rule was stored as %+v", updated.MFA)
	}
	if code := h.do(t, http.MethodPut, "/api/v1/idps/"+created.ID, body(nil), &updated); code != http.StatusOK {
		t.Fatalf("update without a rule: %d", code)
	}
	if !slices.Equal(updated.MFA.AMR, []string{"mfa", "hwk"}) || !slices.Equal(updated.MFA.ACR, []string{"phr"}) {
		t.Fatalf("an update that left the rule out changed it to %+v", updated.MFA)
	}
	if code := h.do(t, http.MethodPut, "/api/v1/idps/"+created.ID, body(map[string]any{"amr": []string{}, "acr": []string{}}), &updated); code != http.StatusOK {
		t.Fatalf("update to no rule: %d", code)
	}
	if len(updated.MFA.AMR) != 0 || len(updated.MFA.ACR) != 0 {
		t.Fatalf("an empty rule was stored as %+v", updated.MFA)
	}
	if code := h.do(t, http.MethodPut, "/api/v1/idps/"+created.ID, body(map[string]any{"amr": []string{"pwd"}}), nil); code != http.StatusBadRequest {
		t.Fatalf("a rule counting a password: %d, want it refused", code)
	}
	gh := map[string]any{"preset": "github", "clientId": "gh-client", "clientSecret": "gh-secret", // gitleaks:allow
		"mfa": map[string]any{"amr": []string{"mfa"}}}
	if code := h.do(t, http.MethodPost, "/api/v1/idps", gh, nil); code != http.StatusBadRequest {
		t.Fatalf("a GitHub provider with a rule: %d, want it refused", code)
	}

	// The rule is part of the provider's history, and restoring the
	// revision before it was emptied puts it back.
	octx := tenant.WithOrg(context.Background(), admin.Org.ID)
	list, err := h.deps.SSO.List(octx, admin.Org.ID)
	if err != nil || len(list) != 1 || len(list[0].MFA.AMR) != 0 {
		t.Fatalf("list: %v %+v", err, list)
	}
	var restored provider
	if code := h.do(t, http.MethodPost, "/api/v1/idps/"+created.ID+"/revisions/2/restore", nil, &restored); code != http.StatusOK {
		t.Fatalf("restore: %d", code)
	}
	if !slices.Equal(restored.MFA.AMR, []string{"mfa", "hwk"}) || !slices.Equal(restored.MFA.ACR, []string{"phr"}) {
		t.Fatalf("restoring revision 2 put back the rule %+v", restored.MFA)
	}
}

// TestOIDCReauthDowngradeMovesTokenAMR consents from a session that had a
// second factor, then re-authenticates without one. The client's refresh
// tokens move to the new session and take its amr, so the next refresh
// yields an access token, and an introspection answer, that no longer
// claim "mfa".
func TestOIDCReauthDowngradeMovesTokenAMR(t *testing.T) {
	h := start(t)
	b, admin := newSSOBrowser(t, h, "E2E OIDC MFA token downgrade")
	b.idp.authTime = func() int64 { return time.Now().Unix() }
	b.idp.amr = []string{"pwd", "mfa"}
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
	introspect := introspector(t, h, admin.Org.ID, admin.User.ID)
	if got := claimAMR(jwtClaims(t, access)); !slices.Equal(got, []string{"pwd", "mfa"}) {
		t.Fatalf("amr at consent = %v, want [pwd mfa]", got)
	}

	h.ageSessions(t, sess.User.ID)
	b.idp.amr = []string{"pwd"}
	if end := b.follow(t, sess.SignIn.ReauthURL+"&next=/connectors"); end.Path != "/connectors" {
		t.Fatalf("the re-authentication ended at %s", end)
	}
	status, body := c.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
	if status != http.StatusOK {
		t.Fatalf("refresh after the re-authentication: %d %v", status, body)
	}
	renewed, _ := body["access_token"].(string)
	if got := claimAMR(jwtClaims(t, renewed)); !slices.Equal(got, []string{"pwd"}) {
		t.Errorf("amr after a re-authentication without a second factor = %v, want [pwd]", got)
	}
	if in := introspect(renewed); !in.Active || !slices.Equal(in.AMR, []string{"pwd"}) {
		t.Errorf("introspection after the re-authentication = %+v, want active with amr [pwd]", in)
	}
}

// TestIDPUpdateMFARule changes only the second-factor rule through its
// own route. A change made to the provider in between, which a PUT built
// from an earlier read would undo, stays; the change is revisioned; and
// the route asks what an update asks.
func TestIDPUpdateMFARule(t *testing.T) {
	h := start(t)
	idp := newFakeIdP(t)
	admin := h.register(t, "E2E IdP rule patch")
	type provider struct {
		ID             string      `json:"id"`
		Enabled        bool        `json:"enabled"`
		AllowedDomains []string    `json:"allowedDomains"`
		MFA            sso.MFARule `json:"mfa"`
	}
	var created provider
	if code := h.do(t, http.MethodPost, "/api/v1/idps", map[string]any{"name": "Patch IdP", "preset": "generic",
		"issuer": idp.URL, "clientId": idp.clientID, "clientSecret": "test-secret", "enabled": true}, // gitleaks:allow
		&created); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	path := "/api/v1/idps/" + created.ID
	// Someone turns the provider off and narrows its domains after the
	// editor read it.
	if code := h.do(t, http.MethodPut, path, map[string]any{"name": "Patch IdP", "preset": "generic",
		"issuer": idp.URL, "clientId": idp.clientID, "enabled": false, "allowedDomains": []string{"example.test"}},
		nil); code != http.StatusOK {
		t.Fatalf("update: %d", code)
	}

	var patched provider
	if code := h.do(t, http.MethodPatch, path+"/mfa", map[string]any{"amr": []string{"mfa"}, "acr": []string{"phr"}},
		&patched); code != http.StatusOK {
		t.Fatalf("patch the rule: %d", code)
	}
	if patched.Enabled || !slices.Equal(patched.AllowedDomains, []string{"example.test"}) {
		t.Errorf("changing the rule changed the rest: enabled %v, domains %v", patched.Enabled, patched.AllowedDomains)
	}
	if !slices.Equal(patched.MFA.AMR, []string{"mfa"}) || !slices.Equal(patched.MFA.ACR, []string{"phr"}) {
		t.Errorf("the rule was stored as %+v", patched.MFA)
	}
	list, err := h.deps.SSO.List(tenant.WithOrg(context.Background(), admin.Org.ID), admin.Org.ID)
	if err != nil || len(list) != 1 || list[0].Enabled || !slices.Equal(list[0].MFA.ACR, []string{"phr"}) {
		t.Fatalf("stored provider: %v %+v", err, list)
	}
	revs := h.history(t, path)
	if len(revs) != 3 || revs[0].Revision != 3 || revs[0].Action != "update" || revs[0].Diff == nil {
		t.Fatalf("history after the rule change: %+v", revs)
	}

	if code := h.do(t, http.MethodPatch, path+"/mfa", map[string]any{"amr": []string{"pwd"}}, nil); code != http.StatusBadRequest {
		t.Errorf("a rule counting a password: %d, want 400", code)
	}
	var gh provider
	if code := h.do(t, http.MethodPost, "/api/v1/idps", map[string]any{"preset": "github", "clientId": "gh-client",
		"clientSecret": "gh-secret"}, &gh); code != http.StatusCreated { // gitleaks:allow
		t.Fatalf("create GitHub provider: %d", code)
	}
	if code := h.do(t, http.MethodPatch, "/api/v1/idps/"+gh.ID+"/mfa", map[string]any{"amr": []string{"mfa"}}, nil); code != http.StatusBadRequest {
		t.Errorf("a rule on a GitHub provider: %d, want 400", code)
	}
	if code := h.do(t, http.MethodPatch, "/api/v1/idps/no-such-provider/mfa", map[string]any{"amr": []string{"mfa"}}, nil); code != http.StatusNotFound {
		t.Errorf("a rule on a provider that does not exist: %d, want 404", code)
	}

	// Like any change to who may sign in, it needs a recent sign-in.
	h.ageSessions(t, admin.User.ID)
	var ref refusal
	if code := h.do(t, http.MethodPatch, path+"/mfa", map[string]any{"amr": []string{}}, &ref); code != http.StatusForbidden || ref.code() != "reauth_required" {
		t.Errorf("a stale session changing the rule: %d %+v, want 403 reauth_required", code, ref)
	}
}
