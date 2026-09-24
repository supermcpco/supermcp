package saml

import "testing"

// Where somebody lands after signing in comes from a query parameter, so
// it is the classic open redirect: a value that leaves the site turns a
// sign-in link into a way to send people somewhere else, with this
// instance's name on the link.
func TestSafeRedirectStaysOnThisSite(t *testing.T) {
	for in, want := range map[string]string{
		"/dashboard":                "/dashboard",
		"/connectors?tab=installed": "/connectors?tab=installed",
		"":                          "",
		"https://evil.example":      "",
		"//evil.example":            "",
		`/\evil.example`:            "", // a browser reads this as protocol-relative
		`/\/evil.example`:           "",
		"javascript:alert(1)":       "",
		"dashboard":                 "",
		"/":                         "/",
	} {
		if got := safeRedirect(in); got != want {
			t.Errorf("safeRedirect(%q) = %q, wanted %q", in, got, want)
		}
	}
}
