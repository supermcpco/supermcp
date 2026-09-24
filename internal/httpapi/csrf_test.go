package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The consumer endpoint is exempt from the cross-site check because a SAML
// assertion is a cross-site POST by construction. The exemption has to be
// that one path and nothing near it.
func TestOnlyTheSAMLConsumerIsExemptFromTheCrossSiteCheck(t *testing.T) {
	for name, tc := range map[string]struct {
		method, path string
		want         bool
	}{
		"the consumer":            {http.MethodPost, "/api/v1/auth/saml/idp_1/acs", true},
		"the consumer by GET":     {http.MethodGet, "/api/v1/auth/saml/idp_1/acs", false},
		"the metadata document":   {http.MethodPost, "/api/v1/auth/saml/idp_1/metadata", false},
		"something below it":      {http.MethodPost, "/api/v1/auth/saml/idp_1/acs/more", false},
		"no provider named":       {http.MethodPost, "/api/v1/auth/saml//acs", false},
		"the prefix on its own":   {http.MethodPost, "/api/v1/auth/saml/", false},
		"a path that starts like": {http.MethodPost, "/api/v1/auth/saml-providers", false},
		"an ordinary admin call":  {http.MethodPost, "/api/v1/connectors", false},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		if got := isSAMLConsumer(r); got != tc.want {
			t.Errorf("%s (%s %s): exempt = %v, wanted %v", name, tc.method, tc.path, got, tc.want)
		}
	}
}

// And the middleware itself must still refuse an ordinary cross-site POST.
func TestCrossSitePostIsStillRefused(t *testing.T) {
	var reached bool
	h := csrf(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	r := httptest.NewRequest(http.MethodPost, "/api/v1/connectors", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if reached || w.Code != http.StatusForbidden {
		t.Errorf("a cross-site POST reached the handler (code %d)", w.Code)
	}

	reached = false
	r = httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/idp_1/acs", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !reached {
		t.Error("the SAML consumer was blocked, so no assertion could ever be delivered")
	}
}
