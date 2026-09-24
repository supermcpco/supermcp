package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/supermcpco/supermcp/internal/mcpauth"
)

// Everything the command refuses before it opens a database: an operator
// who mistypes gets the usage, not a connection error about a database
// they did not mean to touch.
func TestOAuthClientsRefusesBadArgumentsBeforeTouchingTheDatabase(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://nobody@127.0.0.1:1/none")
	cases := []struct {
		args []string
		want string
	}{
		{nil, "oauth clients list|approve|reject"},
		{[]string{"tokens"}, "oauth clients list|approve|reject"},
		{[]string{"clients"}, "oauth clients list|approve|reject"},
		{[]string{"clients", "purge"}, `unknown subcommand "purge"`},
		{[]string{"clients", "list", "-status", "waiting"}, `-status: unknown format "waiting"`},
		{[]string{"clients", "list", "-format", "csv"}, `unknown format "csv"`},
		{[]string{"clients", "approve"}, "usage: supermcp oauth clients approve [-by name] <client_id>"},
		{[]string{"clients", "reject", "a", "b"}, "usage: supermcp oauth clients reject [-by name] <client_id>"},
	}
	for _, c := range cases {
		err := oauthCmd(c.args)
		if err == nil {
			t.Errorf("%v: accepted", c.args)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: got %q, want it to mention %q", c.args, err, c.want)
		}
	}
}

func TestOAuthClientsListOutput(t *testing.T) {
	when := time.Date(2026, 9, 24, 8, 30, 0, 0, time.UTC)
	clients := []mcpauth.ClientInfo{
		{ClientID: "cid_1", Name: "Claude Desktop", Status: "pending", CreatedAt: when,
			RegistrationIP: "203.0.113.9", RedirectURIs: []string{"http://127.0.0.1/cb", "https://app.example/cb"}},
		{ClientID: "cid_2", Name: "CI", Status: "approved", CreatedAt: when},
	}

	var text bytes.Buffer
	if err := writeClients(&text, clients, "text"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(text.String(), "\n"), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "CLIENT ID") {
		t.Fatalf("table:\n%s", text.String())
	}
	for _, want := range []string{"cid_1", "Claude Desktop", "pending", "2026-09-24 08:30", "203.0.113.9", "http://127.0.0.1/cb https://app.example/cb"} {
		if !strings.Contains(lines[1], want) {
			t.Errorf("the first row lacks %q: %s", want, lines[1])
		}
	}

	var asJSON bytes.Buffer
	if err := writeClients(&asJSON, clients, "json"); err != nil {
		t.Fatal(err)
	}
	var back []mcpauth.ClientInfo
	if err := json.Unmarshal(asJSON.Bytes(), &back); err != nil {
		t.Fatalf("the JSON does not parse: %v\n%s", err, asJSON.String())
	}
	if len(back) != 2 || back[0].ClientID != "cid_1" || back[1].Status != "approved" {
		t.Errorf("the JSON round trip changed the list: %+v", back)
	}

	var none bytes.Buffer
	if err := writeClients(&none, nil, "text"); err != nil || none.String() != "no clients\n" {
		t.Errorf("an empty list printed %q (%v)", none.String(), err)
	}
}
