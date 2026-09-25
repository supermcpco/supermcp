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

// fresh reports whether p may perform a guarded operation now. Anything
// other than a browser session passes; a session passes when it
// authenticated within window. A session with no recorded time fails,
// which is the safe reading of a row nothing has vouched for.
func fresh(p *authz.Principal, window time.Duration, now time.Time) bool {
	if p.AuthMethod != "session" {
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
// provider again. The start endpoints take reauth=1 for that: the
// provider is asked to authenticate the person afresh (prompt=login for
// OpenID Connect, ForceAuthn for SAML), and the browser carries the id of
// the session being replaced through the round trip. The callback opens a
// new session, which is fresh because it is new, and revokes the one it
// replaces when both belong to the same person. The SAML consumer is
// reached by a cross-site POST that carries no Lax cookie, the session
// cookie included, which is why the id travels in a cookie of its own.
//
// The cookie holds the session's id, the digest stored in the table, not
// the secret the session cookie holds; knowing it lets nobody act as the
// session. The worst a forged one can do is have a person's sign-in end
// another of that same person's sessions.
const (
	reauthFlowCookie = "sm_reauth"
	reauthFlowTTL    = 15 * time.Minute
)

// reauthStart, on a sign-in asked for as a re-authentication, remembers
// which session the browser holds so the callback can retire it.
func (d Deps) reauthStart(w http.ResponseWriter, r *http.Request, crossSite bool) {
	if r.URL.Query().Get("reauth") != "1" {
		return
	}
	if p, ok := authz.From(r.Context()); ok && p.AuthMethod == "session" && p.SessionID != "" {
		w.Header().Add("Set-Cookie", d.flowCookie(reauthFlowCookie, p.SessionID, int(reauthFlowTTL.Seconds()), crossSite))
	}
}

// reauthFinish returns the session a re-authentication replaces, if any,
// and clears the cookie that named it whatever happens next.
func (d Deps) reauthFinish(w http.ResponseWriter, r *http.Request, crossSite bool) string {
	c, err := r.Cookie(d.flowCookieName(reauthFlowCookie))
	if err != nil || c.Value == "" {
		return ""
	}
	w.Header().Add("Set-Cookie", d.flowCookie(reauthFlowCookie, "", 0, crossSite))
	return c.Value
}

// retireReplaced revokes the session a re-authentication replaced, when
// it is still live and belongs to the person who just signed in. It
// reports whether it did. A failure is logged and not fatal: the new
// session is already open, and the old one still expires on its own.
func (d Deps) retireReplaced(ctx context.Context, sessionID, userID string) bool {
	if sessionID == "" {
		return false
	}
	old, err := d.Identity.LoadSession(ctx, sessionID)
	if err != nil || old.UserID != userID {
		return false
	}
	if err := d.Identity.RevokeSession(ctx, sessionID, "replaced by re-authentication"); err != nil {
		if d.Log != nil {
			d.Log.Warn("could not end the session a re-authentication replaced", "err", err)
		}
		return false
	}
	return true
}

// signInFor describes a browser session's sign-in for the session
// bootstrap. The provider's name is looked up rather than stored, so a
// renamed provider shows its new name; a provider that is gone or turned
// off leaves the name empty and the client falls back to the sign-in page.
func (d Deps) signInFor(ctx context.Context, p *authz.Principal) *signInDTO {
	if p.AuthMethod != "session" || p.SignIn.Method == "" {
		return nil
	}
	out := &signInDTO{Method: p.SignIn.Method, ProviderID: p.SignIn.ProviderID,
		AuthenticatedAt: p.SignIn.At, FreshUntil: p.SignIn.At.Add(d.freshWindow())}
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
			if l.ID == p.SignIn.ProviderID {
				out.ProviderName = l.Name
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
				out.ProviderName = l.Name
				out.ReauthURL = "/api/v1/auth/saml/" + url.PathEscape(l.ID) + "/login?reauth=1"
			}
		}
	}
	return out
}
