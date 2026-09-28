package connector_test

import (
	"reflect"
	"testing"

	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// TestListCredentials checks that List reports each connector's
// credentials exactly as Get does, and only the org's own connectors.
// Requires DATABASE_URL; skipped otherwise.
func TestListCredentials(t *testing.T) {
	f := newFixture(t) // "Example": bearer {{env.TOKEN}}
	other := newFixture(t)
	ctx := t.Context()

	create := func(t *testing.T, name string, a adapter.Auth) *connector.Connector {
		t.Helper()
		c, err := f.svc.Create(ctx, f.orgID, connector.CreateInput{
			Name:      name,
			Transport: adapter.Transport{Type: adapter.TransportHTTP, BaseURL: "https://api.example.com/v1"},
			Auth:      a,
			Tools:     []adapter.Tool{*def(t, "list_items", "GET", "/items")},
			CreatedBy: "user_1",
		})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	basic := create(t, "Basic", adapter.Auth{Type: adapter.AuthBasic, Username: "{{env.USER}}", Password: "{{env.PASS}}"})
	none := create(t, "None", adapter.Auth{Type: adapter.AuthNone})

	// Credential values are sealed in production; the list reads only
	// names and the secret flag, so a placeholder value is enough here.
	seed := `INSERT INTO connector_credentials (connector_id, organization_id, name, value_enc, secret) VALUES ($1, $2, $3, '\x00', $4)`
	f.exec(t, seed, f.conn.ID, f.orgID, "TOKEN", true)
	f.exec(t, seed, f.conn.ID, f.orgID, "UNUSED", true) // stored but referenced nowhere
	f.exec(t, seed, basic.ID, f.orgID, "USER", false)
	f.exec(t, seed, other.conn.ID, other.orgID, "TOKEN", true)

	want := map[string][]connector.CredentialInfo{
		f.conn.ID: {{Name: "TOKEN", Set: true, Secret: true, Required: true}},
		basic.ID: {
			{Name: "USER", Set: true, Secret: false, Required: true},
			{Name: "PASS", Set: false, Secret: true, Required: true},
		},
		none.ID: nil,
	}

	list, err := f.svc.List(ctx, f.orgID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != len(want) {
		t.Fatalf("List returned %d connectors, want %d", len(list), len(want))
	}
	for _, c := range list {
		w, ok := want[c.ID]
		if !ok {
			t.Fatalf("List returned connector %s (org %s), not one of this org's", c.ID, c.OrgID)
		}
		if !reflect.DeepEqual(c.Credentials, w) {
			t.Errorf("%s: List credentials %+v, want %+v", c.Name, c.Credentials, w)
		}
		got, err := f.svc.Get(ctx, f.orgID, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(c.Credentials, got.Credentials) {
			t.Errorf("%s: List credentials %+v, Get %+v", c.Name, c.Credentials, got.Credentials)
		}
	}
}
