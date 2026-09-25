package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/config"
	"github.com/supermcpco/supermcp/internal/identity"
)

// reauthRequired is the stable code a client reads from errors[].value,
// and the prefix of the detail, when an operation refuses a session that
// signed in too long ago. The web client answers it by asking the person
// to sign in again and repeating the request.
const reauthRequired = "reauth_required"

// freshWindow is how recently a session must have authenticated for the
// operations requireFresh guards.
func (d Deps) freshWindow() time.Duration {
	if d.Config == nil || d.Config.AuthFreshWindow <= 0 {
		return config.DefaultAuthFreshWindow
	}
	return d.Config.AuthFreshWindow
}

// requireFresh is require for the operations that hand out credentials,
// change who may do what, or change the security settings: on top of the
// permission, a browser session must have signed in, or re-authenticated,
// within the freshness window. A session cookie lives for up to thirty
// days; this is what stops one that was left open or lifted from a
// machine from minting a key or granting itself a role.
//
// The permission is checked first, so a caller who could never do this
// is told so rather than asked for a password to be told so afterwards.
//
// Only browser sessions are held to it. API keys, OAuth access tokens and
// service accounts (client_credentials) are not signed in by a person and
// have nobody to ask; they pass on their permission and scopes alone.
func (d Deps) requireFresh(ctx context.Context, perm authz.Permission, r authz.Resource) (*authz.Principal, error) {
	p, err := d.require(ctx, perm, r)
	if err != nil {
		return nil, err
	}
	if err := d.checkFresh(ctx, p, perm, r); err != nil {
		return nil, err
	}
	return p, nil
}

// checkFresh refuses a stale browser session and records the refusal,
// without the request body. perm names what was asked for in the record
// and may be empty for an operation no permission guards.
func (d Deps) checkFresh(ctx context.Context, p *authz.Principal, perm authz.Permission, r authz.Resource) error {
	if fresh(p, d.freshWindow(), time.Now()) {
		return nil
	}
	meta := map[string]any{"reason": reauthRequired, "authenticatedAt": p.SignIn.At, "window": d.freshWindow().String()}
	if perm != "" {
		meta["permission"] = string(perm)
	}
	d.emit(ctx, audit.Event{
		Category: audit.CategoryAuthz, Action: "access.denied", Outcome: audit.Denied,
		TargetKind: targetKindFor(r), TargetID: targetIDFor(r), Meta: meta,
	})
	return errReauthRequired(d.freshWindow())
}

// nonInteractive are the credentials no person signs in with, and so
// none that could be asked to sign in again: API keys, OAuth access
// tokens and service accounts (client_credentials). They are named here
// rather than inferred, so a kind of credential added later is held to
// the window until somebody decides otherwise.
var nonInteractive = map[string]bool{"api_key": true, "oauth_at": true, "client_credentials": true}

// fresh reports whether p may perform a guarded operation now. The
// non-interactive credentials pass; everything else, a browser session
// included, passes only when it authenticated within window. A time
// nobody vouched for fails.
func fresh(p *authz.Principal, window time.Duration, now time.Time) bool {
	if nonInteractive[p.AuthMethod] {
		return true
	}
	if p.SignIn.At.IsZero() {
		return false
	}
	return now.Sub(p.SignIn.At) <= window
}

// errReauthRequired is the refusal. It is a 403 rather than a 401: the
// session is valid and stays valid for everything else, and a client
// that treated this as signed-out would throw away a working session.
func errReauthRequired(window time.Duration) error {
	msg := "sign in again to continue: this action needs a sign-in from the last " + humanWindow(window)
	return huma.Error403Forbidden(reauthRequired+": "+msg,
		&huma.ErrorDetail{Location: "session", Message: msg, Value: reauthRequired})
}

// humanWindow writes a window the way the refusal reads it.
func humanWindow(d time.Duration) string {
	if d%time.Hour == 0 {
		if d == time.Hour {
			return "hour"
		}
		return itoa(int(d/time.Hour)) + " hours"
	}
	if d%time.Minute == 0 {
		if d == time.Minute {
			return "minute"
		}
		return itoa(int(d/time.Minute)) + " minutes"
	}
	return d.String()
}

// reauthOutput reports when the session last authenticated, and until
// when that counts as fresh.
type reauthOutput struct {
	Body struct {
		AuthenticatedAt time.Time `json:"authenticatedAt" doc:"When this session last proved who is using it"`
		FreshUntil      time.Time `json:"freshUntil" doc:"Until when sensitive operations are allowed without signing in again"`
	}
}

func (d Deps) reauthRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "reauthenticate", Method: http.MethodPost,
		Path:    "/api/v1/auth/reauth",
		Summary: "Confirm your password to continue with a sensitive action",
		Description: "Re-authenticates the current password session: the session keeps its cookie and its id, and its " +
			"authentication time becomes now. A wrong password counts toward the same lockout as sign-in. A session " +
			"signed in through single sign-on re-authenticates by signing in through its provider again instead " +
			"(the start endpoint with reauth=1).",
		Tags: []string{"auth"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			Body struct {
				Password string `json:"password" minLength:"1" maxLength:"1024"`
			}
		}) (*reauthOutput, error) {
			p, ok := authz.From(ctx)
			if !ok || p.AuthMethod != "session" || p.SessionID == "" {
				return nil, huma.Error401Unauthorized("authentication required")
			}
			sess, err := d.Identity.LoadSession(ctx, p.SessionID)
			if err != nil {
				return nil, huma.Error401Unauthorized("authentication required")
			}
			ip, _ := ctx.Value(ipKey).(string)
			at, err := d.Identity.Reauthenticate(ctx, sess, in.Body.Password, ip)
			if err != nil {
				d.emit(ctx, audit.Event{Category: audit.CategoryAuth, Action: "session.reauth", Outcome: audit.Failure,
					TargetKind: "session", TargetID: sess.ID, Meta: map[string]any{"method": "password", "reason": err.Error()}})
				return nil, reauthErr(err)
			}
			d.emit(ctx, audit.Event{Category: audit.CategoryAuth, Action: "session.reauth", Outcome: audit.Success,
				TargetKind: "session", TargetID: sess.ID, Meta: map[string]any{"method": "password"}})
			out := &reauthOutput{}
			out.Body.AuthenticatedAt, out.Body.FreshUntil = at, at.Add(d.freshWindow())
			return out, nil
		})
}

// reauthErr maps a failed re-authentication. The wrong password is a 400,
// not the 401 a failed sign-in gets: the session is still good, and a
// client that read 401 as signed out would drop it.
func reauthErr(err error) error {
	switch {
	case errors.Is(err, identity.ErrReauthViaProvider):
		return huma.Error409Conflict(err.Error())
	case errors.Is(err, identity.ErrSessionInvalid):
		return huma.Error401Unauthorized("authentication required")
	}
	return humaErr(err)
}

// A single sign-on session re-authenticates by signing in through its
// provider again. The start endpoints take reauth=1 for that. Begin
// records the session being replaced on the sign-in's own request row, so
// only the callback answering that sign-in reads it back, and asks the
// provider to authenticate the person afresh (prompt=login and max_age=0
// for OpenID Connect, ForceAuthn for SAML).
//
// Having asked proves nothing: GitHub ignores the parameters, and any
// provider may answer from a session it already holds. So the callback
// judges the answer by the time the provider says the person
// authenticated (auth_time from a verified ID token, AuthnInstant from a
// signed assertion). A re-authentication is accepted only when that time
// is within the window and the person, workspace and provider are those
// of the session being replaced. Then a new session opens carrying that
// time, and the old one is ended. Otherwise no session opens, the old one
// is left exactly as it was, and the browser goes to /reauth with the
// reason.

// Reasons a re-authentication through a provider is refused. The web
// client turns each into a sentence on its /reauth page.
const (
	reauthMismatch    = "reauth_mismatch"
	reauthUnconfirmed = "reauth_unconfirmed"
	reauthNotRecent   = "reauth_not_recent"
)

// reauthReplaces returns the session a sign-in started with reauth=1
// would replace: the one the browser holds, if any.
func reauthReplaces(r *http.Request) string {
	if r.URL.Query().Get("reauth") != "1" {
		return ""
	}
	if p, ok := authz.From(r.Context()); ok && p.AuthMethod == "session" {
		return p.SessionID
	}
	return ""
}

// providerSignIn is what either protocol's callback knows once the
// provider's answer has been verified and linked to an account.
type providerSignIn struct {
	UserID, OrgID, Email, ProviderID, ProviderName string
	// Method is sso or saml.
	Method string
	// At is when the provider says the person authenticated; nil when it
	// did not say.
	At *time.Time
	// Replaces is the session a re-authentication was started from.
	Replaces string
	// Verified says the provider vouched for the person's factors, which
	// the session records for policies that require one.
	Verified bool
	Next     string
	Meta     map[string]any
}

// vouchedTime is what a provider's authentication time is worth: its
// time, but never later than now, since a clock running ahead must not
// buy a sign-in that stays fresh for longer. Zero when it did not say.
func vouchedTime(at *time.Time, now time.Time) time.Time {
	if at == nil || at.IsZero() {
		return time.Time{}
	}
	if at.After(now) {
		return now
	}
	return *at
}

// judgeReauth decides whether a sign-in may replace the session it was
// started to re-authenticate. It returns that session and "" to go
// ahead, nil and "" when there is nothing to replace (an ordinary
// sign-in, or the session has ended since), or a reason to refuse.
func (d Deps) judgeReauth(ctx context.Context, in providerSignIn, now time.Time) (*identity.Session, string) {
	if in.Replaces == "" {
		return nil, ""
	}
	old, err := d.Identity.LoadSession(ctx, in.Replaces)
	if err != nil {
		return nil, ""
	}
	if old.UserID != in.UserID || old.OrgID != in.OrgID || old.AuthProviderID != in.ProviderID {
		return old, reauthMismatch
	}
	at := vouchedTime(in.At, now)
	if at.IsZero() {
		return old, reauthUnconfirmed
	}
	if now.Sub(at) > d.freshWindow() {
		return old, reauthNotRecent
	}
	return old, ""
}

// finishProviderSignIn opens the session a verified provider sign-in
// earned, or refuses a re-authentication that does not hold up, and
// sends the browser on. fail is the protocol's own failure page.
func (d Deps) finishProviderSignIn(w http.ResponseWriter, r *http.Request, in providerSignIn, fail func(error)) {
	ctx := r.Context()
	ip, _ := ctx.Value(ipKey).(string)
	now := time.Now()
	next := in.Next
	if next == "" {
		next = "/"
	}
	old, reason := d.judgeReauth(ctx, in, now)
	if reason != "" {
		// No session opens: the one being replaced stays exactly as it
		// was, stale, and the person is told why.
		meta := map[string]any{"method": in.Method, "provider": in.ProviderName, "reason": reason}
		if in.At != nil {
			meta["providerAuthenticatedAt"] = *in.At
		}
		d.emitAs(ctx, audit.Event{OrgID: old.OrgID, Category: audit.CategoryAuth, Action: "session.reauth",
			Outcome: audit.Failure, ActorKind: "user", ActorID: old.UserID,
			TargetKind: "session", TargetID: old.ID, SessionID: old.ID, Meta: meta})
		//nolint:gosec // a fixed local path; next was kept local by the provider package
		http.Redirect(w, r, "/reauth?error="+reason+"&next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	sess, err := d.Identity.CreateSession(ctx, in.UserID, in.OrgID, in.Method, in.ProviderID,
		vouchedTime(in.At, now), ip, r.UserAgent())
	if err != nil {
		fail(err)
		return
	}
	meta := in.Meta
	if old != nil {
		if err := d.Identity.RevokeSession(ctx, old.ID, "replaced by re-authentication"); err != nil && d.Log != nil {
			// The new session is open and fresh; the old one still
			// expires on its own.
			d.Log.Warn("could not end the session a re-authentication replaced", "err", err)
		}
		meta["reauth"] = true
		d.emitAs(ctx, audit.Event{OrgID: in.OrgID, Category: audit.CategoryAuth, Action: "session.reauth",
			Outcome: audit.Success, ActorKind: "user", ActorID: in.UserID, ActorDisplay: in.Email,
			TargetKind: "session", TargetID: old.ID, SessionID: sess.ID,
			Meta: map[string]any{"method": in.Method, "provider": in.ProviderName, "replacedBy": sess.ID}})
	}
	d.emitAs(ctx, audit.Event{OrgID: in.OrgID, Category: audit.CategoryAuth, Action: "session.create",
		Outcome: audit.Success, ActorKind: "user", ActorID: in.UserID, ActorDisplay: in.Email,
		SessionID: sess.ID, Meta: meta})
	if in.Verified {
		if err := d.Identity.MarkVerified(ctx, sess.ID); err != nil && d.Log != nil {
			d.Log.Warn("could not record the provider's verification", "session", sess.ID, "err", err)
		}
	}
	w.Header().Add("Set-Cookie", d.cookieValue(sess.Secret, int(d.Identity.Cfg.SessionAbsolute.Seconds())))
	//nolint:gosec // next was kept local by the provider package
	http.Redirect(w, r, next, http.StatusFound)
}

// signInFor describes a browser session's sign-in for the session
// bootstrap. The provider's name is looked up rather than stored, so a
// renamed provider shows its new name; a provider that is gone or turned
// off leaves the name and the URL empty.
func (d Deps) signInFor(ctx context.Context, p *authz.Principal) *signInDTO {
	if p.AuthMethod != "session" || p.SignIn.Method == "" {
		return nil
	}
	out := &signInDTO{Method: p.SignIn.Method, ProviderID: p.SignIn.ProviderID, CanReauth: p.SignIn.Method == "password"}
	if !p.SignIn.At.IsZero() {
		at, until := p.SignIn.At, p.SignIn.At.Add(d.freshWindow())
		out.AuthenticatedAt, out.FreshUntil = &at, &until
	}
	if p.SignIn.ProviderID == "" {
		return out
	}
	switch p.SignIn.Method {
	case "sso":
		if d.SSO == nil {
			return out
		}
		list, err := d.SSO.Listings(ctx)
		if err != nil {
			return out
		}
		for _, l := range list {
			if l.ID != p.SignIn.ProviderID {
				continue
			}
			out.ProviderName = l.Name
			if ok, err := d.SSO.ConfirmsSignIn(ctx, l.ID); err == nil && ok {
				out.CanReauth = true
				out.ReauthURL = "/auth/sso/" + url.PathEscape(l.ID) + "/start?reauth=1"
			}
		}
	case "saml":
		if d.SAML == nil {
			return out
		}
		list, err := d.SAML.Listings(ctx)
		if err != nil {
			return out
		}
		for _, l := range list {
			if l.ID == p.SignIn.ProviderID {
				// An assertion carries AuthnInstant, so a SAML provider
				// can always say when the person authenticated.
				out.ProviderName = l.Name
				out.CanReauth = true
				out.ReauthURL = "/api/v1/auth/saml/" + url.PathEscape(l.ID) + "/login?reauth=1"
			}
		}
	}
	return out
}
