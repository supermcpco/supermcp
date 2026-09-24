package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

// A sign-in that leaves this instance and comes back — to an identity
// provider and back — has to return to the browser that started it. The
// provider will issue an answer to anybody who asks for one, so without
// this somebody signs in as themselves, delivers the answer to another
// person's browser, and that person is signed in as them: everything they
// do next, every credential they connect, lands in the attacker's
// account. The cookie is the proof that the browser holding it is the one
// that asked.

const (
	samlFlowCookie = "sm_saml"
	ssoFlowCookie  = "sm_sso"
	// Long enough to sign in with a second factor, short enough that an
	// abandoned attempt is not left lying around.
	samlFlowTTL = 15 * time.Minute
	ssoFlowTTL  = 15 * time.Minute
)

// newFlowSecret mints the value the browser carries. Only its digest is
// stored, so the table cannot be used to finish somebody else's sign-in.
func newFlowSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// flowCookieName prefixes the cookie with __Host- where the browser will
// enforce it, and falls back to a plain name over http, which is only the
// development case.
func (d Deps) flowCookieName(base string) string {
	if d.Config != nil && d.Config.PublicURL != nil && d.Config.PublicURL.Scheme == "https" {
		return "__Host-" + base
	}
	return base
}

// flowCookie writes one. crossSite is for the SAML consumer, which the
// identity provider reaches by a cross-site form POST: a Lax cookie is
// not sent on one, so the cookie would never arrive and every sign-in
// would fail. SameSite=None demands Secure, which browsers also grant to
// http://localhost, so development still works.
func (d Deps) flowCookie(base, value string, maxAge int, crossSite bool) string {
	https := d.Config != nil && d.Config.PublicURL != nil && d.Config.PublicURL.Scheme == "https"
	c := d.flowCookieName(base) + "=" + value + "; Path=/; HttpOnly"
	switch {
	case crossSite:
		c += "; SameSite=None; Secure"
	case https:
		c += "; SameSite=Lax; Secure"
	default:
		c += "; SameSite=Lax"
	}
	return c + "; Max-Age=" + itoa(maxAge)
}
