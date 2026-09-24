package authz

import (
	"context"
	"testing"
)

// TestScopeCeiling covers the refusals a scoped credential meets before
// any binding is read. Every case here is decided without a database; the
// grants that need one are covered by the SCIM end-to-end test.
func TestScopeCeiling(t *testing.T) {
	e := &Evaluator{}
	cases := []struct {
		name   string
		scopes []string
		perm   Permission
		reason string
	}{
		{"a provisioning key cannot call tools", []string{ScopeSCIM}, ToolsInvoke, "missing scope " + ScopeToolsInvoke},
		{"a provisioning key cannot read tools", []string{ScopeSCIM}, ToolsRead, "missing scope " + ScopeToolsRead},
		{"a provisioning key cannot change settings", []string{ScopeSCIM}, ConnectorsCreate, "scoped credential cannot connectors:create"},
		{"a tool key cannot provision", []string{ScopeToolsInvoke}, ScimManage, "missing scope " + ScopeSCIM},
		{"a read key cannot provision", []string{ScopeToolsRead}, ScimManage, "missing scope " + ScopeSCIM},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &Principal{Kind: KindUser, ID: "u1", OrgID: "o1", Scopes: c.scopes}
			d, err := e.Evaluate(context.Background(), p, c.perm, Resource{})
			if err != nil {
				t.Fatal(err)
			}
			if d.Allow {
				t.Fatalf("allowed %s with scopes %v", c.perm, c.scopes)
			}
			if d.Reason != c.reason {
				t.Fatalf("reason %q, want %q", d.Reason, c.reason)
			}
		})
	}
}
