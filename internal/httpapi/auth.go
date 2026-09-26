package httpapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/identity/sso"
	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// SessionCookie is the browser session cookie name. The __Host- prefix
// requires Secure and Path=/, which the browser enforces for us.
const SessionCookie = "__Host-sm_sess"
const sessionCookieInsecure = "sm_sess"

// cookieName picks the prefixed name only when cookies will be Secure;
// browsers reject __Host- cookies over plain http (dev on localhost).
func (d Deps) cookieName() string {
	if d.Config.PublicURL != nil && d.Config.PublicURL.Scheme == "https" {
		return SessionCookie
	}
	return sessionCookieInsecure
}

// authenticate resolves a principal from the session cookie or an API key
// and puts it, plus the tenant, in the request context. It never rejects:
// handlers decide what anonymous access means.
func (d Deps) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if p := d.principalFromRequest(r); p != nil {
			ctx = authz.WithPrincipal(ctx, p)
			if p.OrgID != "" {
				ctx = tenant.WithOrg(ctx, p.OrgID)
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (d Deps) principalFromRequest(r *http.Request) *authz.Principal {
	ctx := r.Context()
	// API key: header or bearer token.
	if key := apiKeyFrom(r); key != "" {
		p, err := d.Keys.Authenticate(ctx, key, clientIP(r))
		if err != nil {
			return nil
		}
		return p
	}
	// OAuth access token.
	if tok := bearerFrom(r); tok != "" && d.OAuth != nil {
		p, err := d.OAuth.PrincipalFromToken(ctx, tok)
		if err != nil {
			return nil
		}
		return p
	}
	c, err := r.Cookie(d.cookieName())
	if err != nil || c.Value == "" {
		return nil
	}
	sess, err := d.Identity.LoadSession(ctx, identity.SessionKey(c.Value))
	if err != nil {
		return nil
	}
	email := ""
	if u, err := d.Identity.UserByID(tenant.WithOrg(ctx, sess.OrgID), sess.OrgID, sess.UserID); err == nil {
		email = u.Email
	}
	p := d.Identity.Principal(sess, email)
	d.markPasswordAge(r.Context(), sess, p)
	return p
}

// markPasswordAge flags a principal whose password has outlived the
// workspace's policy. It is checked on every request rather than stored at
// sign-in, so a password that expires during a session, or a policy set
// after it began, still applies. A failure to read the policy leaves the
// session alone: the session itself was just loaded, so this is a
// secondary check, and refusing everyone over it would be an outage.
func (d Deps) markPasswordAge(ctx context.Context, sess *identity.Session, p *authz.Principal) {
	expired, err := d.Identity.SessionPasswordExpired(ctx, sess)
	if err != nil {
		if d.Log != nil {
			d.Log.Warn("could not check the password's age", "user", sess.UserID, "err", err)
		}
		return
	}
	p.PasswordExpired = expired
}

// passwordAgeGate refuses everything but changing the password, reading
// the session and signing out while the password is past its maximum age.
// It covers the OAuth endpoints too: an expired password must not be able
// to grant a client a token that outlives it.
func passwordAgeGate(next http.Handler) http.Handler {
	allowed := map[string]bool{
		"/api/v1/auth/password": true,
		"/api/v1/auth/session":  true,
		"/api/v1/auth/logout":   true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := authz.From(r.Context())
		guarded := strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/oauth/")
		if ok && p.PasswordExpired && guarded && !allowed[r.URL.Path] {
			writeJSONError(w, http.StatusForbidden, "password_expired: your password has expired; change it to continue")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func apiKeyFrom(r *http.Request) string {
	if v := r.Header.Get("X-API-Key"); strings.HasPrefix(v, "smk_") {
		return v
	}
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer smk_") {
		return strings.TrimPrefix(v, "Bearer ")
	}
	return ""
}

// bearerFrom returns a bearer token that is not an API key.
func bearerFrom(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") {
		return ""
	}
	tok := strings.TrimPrefix(v, "Bearer ")
	if strings.HasPrefix(tok, "smk_") {
		return ""
	}
	return tok
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// csrf guards cookie-authenticated mutations. Bearer and API-key requests
// carry no ambient credential, so they are exempt.
func csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if apiKeyFrom(r) != "" {
			next.ServeHTTP(w, r)
			return
		}
		// A SAML assertion arrives as a cross-site form POST from the
		// identity provider, which is what this check exists to stop, so
		// it has to be named. What protects it instead is stronger than an
		// origin: the assertion is signed, it is spent once, and it only
		// finishes the sign-in whose cookie the same browser is carrying.
		if isSAMLConsumer(r) {
			next.ServeHTTP(w, r)
			return
		}
		switch r.Header.Get("Sec-Fetch-Site") {
		case "same-origin", "same-site", "none", "":
			// "" covers non-browser clients; Origin is checked below.
		default:
			writeJSONError(w, http.StatusForbidden, "cross-site request blocked")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r) {
			writeJSONError(w, http.StatusForbidden, "cross-origin request blocked")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isSAMLConsumer matches POST /api/v1/auth/saml/{id}/acs and nothing
// else: a prefix alone would exempt any path under it.
func isSAMLConsumer(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/api/v1/auth/saml/")
	if !ok {
		return false
	}
	id, tail, ok := strings.Cut(rest, "/")
	return ok && id != "" && tail == "acs"
}

func sameOrigin(origin string, r *http.Request) bool {
	host := r.Host
	return strings.HasSuffix(origin, "://"+host)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"title":"` + http.StatusText(status) + `","status":` + itoa(status) + `,"detail":"` + msg + `"}`))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// errStatus maps service errors to HTTP statuses and the message the
// client may see. An error it does not know is a 500 with no message:
// its text can name a host, a DSN or a query, so the caller answers with
// reqid.Message and the text goes to the log.
func errStatus(err error) (int, string) {
	switch {
	case err == nil:
		return http.StatusOK, ""
	case errors.Is(err, authz.ErrDenied):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, identity.ErrWrongPassword):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, identity.ErrInvalidCredentials):
		return http.StatusUnauthorized, "invalid email or password"
	case errors.Is(err, identity.ErrLocked):
		return http.StatusTooManyRequests, err.Error()
	case errors.Is(err, identity.ErrDisabled):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, identity.ErrRegistrationClosed):
		return http.StatusForbidden, identity.RegistrationClosedMessage
	case errors.Is(err, identity.ErrEmailTaken), errors.Is(err, identity.ErrWeakPassword),
		errors.Is(err, identity.ErrPasswordReused):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, identity.ErrPasswordExpired):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, identity.ErrServiceAccountUnknown):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, identity.ErrServiceAccountDisabled):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, sso.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, mcpauth.ErrInvalidKey), errors.Is(err, mcpauth.ErrKeyExpired):
		return http.StatusUnauthorized, err.Error()
	case errors.Is(err, tenant.ErrNoOrg):
		return http.StatusForbidden, "no organisation selected"
	}
	return http.StatusInternalServerError, ""
}

var _ = context.Background

type reqCtxKey int

const (
	ipKey reqCtxKey = iota
	uaKey
)

// requestContext carries the client IP and user agent for handlers that
// record them (sessions, API key use, audit).
func requestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ipKey, clientIP(r))
		ctx = context.WithValue(ctx, uaKey, r.UserAgent())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
