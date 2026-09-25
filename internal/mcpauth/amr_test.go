package mcpauth

import (
	"slices"
	"testing"

	"github.com/supermcpco/supermcp/internal/authz"
)

func TestAMR(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		signIn authz.SignIn
		mfa    bool
		want   []string
	}{
		{"password", authz.SignIn{Method: "password"}, false, []string{"pwd"}},
		{"password with a verified factor", authz.SignIn{Method: "password"}, true, []string{"pwd", "mfa"}},
		{"oidc that reported nothing", authz.SignIn{Method: "sso", Methods: []string{}}, false, nil},
		{"oidc from before methods were kept", authz.SignIn{Method: "sso"}, false, nil},
		{"oidc password only", authz.SignIn{Method: "sso", Methods: []string{"pwd"}}, false, []string{"pwd"}},
		{"oidc that met its rule", authz.SignIn{Method: "sso", Methods: []string{"pwd", "mfa"}}, true, []string{"pwd", "mfa"}},
		{"oidc names its factor", authz.SignIn{Method: "sso", Methods: []string{"pwd", "otp"}}, true, []string{"pwd", "otp", "mfa"}},
		{"oidc hardware key and smart card", authz.SignIn{Method: "sso", Methods: []string{"hwk", "sc"}}, true, []string{"hwk", "sc", "mfa"}},
		// The provider said mfa, but its rule did not count it: the
		// token does not claim what the session does not hold.
		{"oidc mfa the rule did not count", authz.SignIn{Method: "sso", Methods: []string{"pwd", "mfa"}}, false, []string{"pwd"}},
		{"unregistered values are dropped", authz.SignIn{Method: "sso", Methods: []string{"rsa", "ngcmfa", "pwd", "pwd"}}, false, []string{"pwd"}},
		{"saml password", authz.SignIn{Method: "saml", Methods: []string{"pwd"}}, false, []string{"pwd"}},
		{"saml second factor", authz.SignIn{Method: "saml", Methods: []string{}}, true, []string{"mfa"}},
		{"nothing known", authz.SignIn{}, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := AMR(tt.signIn, tt.mfa); !slices.Equal(got, tt.want) {
				t.Errorf("AMR(%+v, %v) = %v, want %v", tt.signIn, tt.mfa, got, tt.want)
			}
		})
	}
}
