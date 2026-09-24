package mcp

import (
	"testing"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/mcpserver"
)

// An assembled surface is shared between requests, so the key has to
// separate every caller the permission check could answer differently
// about. Sharing one across two principals would show one workspace's
// tools to the other.
func TestBuiltKeySeparatesCallers(t *testing.T) {
	srv := &mcpserver.Server{ID: "srv_1", OrgID: "org_1", Version: 3}
	base := &authz.Principal{Kind: authz.KindUser, ID: "u_1", OrgID: "org_1", AuthMethod: "session", Scopes: []string{"a"}}

	same := *base
	if builtKey(srv, base) != builtKey(srv, &same) {
		t.Error("the same caller and server should share a surface")
	}

	for name, change := range map[string]func(p *authz.Principal){
		"a different user":         func(p *authz.Principal) { p.ID = "u_2" },
		"a different kind":         func(p *authz.Principal) { p.Kind = authz.KindServiceAccount },
		"a different organisation": func(p *authz.Principal) { p.OrgID = "org_2" },
		"a bound credential":       func(p *authz.Principal) { p.ServerID = "srv_1" },
		"another scope":            func(p *authz.Principal) { p.Scopes = []string{"a", "b"} },
		"a different auth method":  func(p *authz.Principal) { p.AuthMethod = "api_key" },
		"multi-factor":             func(p *authz.Principal) { p.MFA = true },
	} {
		other := *base
		other.Scopes = append([]string(nil), base.Scopes...)
		change(&other)
		if builtKey(srv, base) == builtKey(srv, &other) {
			t.Errorf("%s shares a surface with the original caller", name)
		}
	}

	// A change to the server itself is a new surface for everyone.
	newer := *srv
	newer.Version = 4
	if builtKey(srv, base) == builtKey(&newer, base) {
		t.Error("a new server version should not reuse the old surface")
	}
}
