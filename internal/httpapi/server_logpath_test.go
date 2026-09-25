package httpapi

import "testing"

// The invitation page carries its token in the path, and the access log
// must not keep it.
func TestLoggedPathHidesInviteToken(t *testing.T) {
	cases := map[string]string{
		"/invite/AbC123-_xyz":       "/invite/{token}",
		"/invite/":                  "/invite/",
		"/invite":                   "/invite",
		"/api/v1/invites/lookup":    "/api/v1/invites/lookup",
		"/api/v1/org/invites/inv_1": "/api/v1/org/invites/inv_1",
		"/healthz":                  "/healthz",
	}
	for in, want := range cases {
		if got := loggedPath(in); got != want {
			t.Errorf("loggedPath(%q) = %q, want %q", in, got, want)
		}
	}
}
