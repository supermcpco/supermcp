package e2e

import (
	"context"
	"net/http"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// The audit trail is only worth having if it records what actually
// happened through the real handlers. These tests drive the HTTP surface
// and then read the stream back, rather than calling the writer directly.

// TestAuditRecordsWhatHappened walks a short session and checks that each
// step left the record an auditor would look for.
func TestAuditRecordsWhatHappened(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	admin := h.register(t, "E2E audit")

	// Something that changes state, something refused, and a credential.
	var key struct {
		Key struct {
			ID string `json:"id"`
		} `json:"key"`
		Secret string `json:"secret"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/api-keys", map[string]any{"name": "auditable"}, &key); code != 200 && code != 201 {
		t.Fatalf("create key: %d", code)
	}
	if code := h.do(t, http.MethodPut, "/api/v1/org/password-policy",
		map[string]any{"minLength": 14, "requireClasses": 2, "history": 3, "maxAgeDays": 0}, nil); code != 200 {
		t.Fatalf("set policy: %d", code)
	}

	events := h.auditEvents(t, ctx, admin.Org.ID)
	byAction := map[string]audit.Record{}
	for _, e := range events {
		byAction[e.Action] = e
	}

	for _, want := range []string{"account.register", "apikey.create", "password_policy.update"} {
		if _, ok := byAction[want]; !ok {
			t.Errorf("nothing in the audit trail records %q; it holds %v", want, actions(events))
		}
	}

	// A registration names the person who did it, not just that it happened.
	if reg := byAction["account.register"]; reg.ActorID != admin.User.ID {
		t.Errorf("the registration event names actor %q, expected %q", reg.ActorID, admin.User.ID)
	}

	// A password policy change records what it changed from and to.
	policy := byAction["password_policy.update"]
	if policy.Diff == nil {
		t.Error("the policy change recorded no difference")
	} else if after, ok := policy.Diff["after"].(map[string]any); !ok || after["minLength"] == nil {
		t.Errorf("the policy change does not say what the minimum length became: %v", policy.Diff)
	}

	// The key's secret must not be anywhere in the stream.
	for _, e := range events {
		if containsSecret(e, key.Secret) {
			t.Fatalf("the audit event %q carries the API key secret", e.Action)
		}
	}
}

// TestAuditRecordsToolCallsAndRefusals covers the two events that come
// from outside the admin API: a tool call through MCP, and a refusal.
func TestAuditRecordsToolCallsAndRefusals(t *testing.T) {
	h := start(t)
	upstream, _ := fakeUpstream(t)
	ctx := context.Background()
	admin := h.register(t, "E2E audit tools")
	octx := tenant.WithOrg(ctx, admin.Org.ID)

	c, err := h.connectors.Create(octx, admin.Org.ID, testConnector(t, upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := h.servers.Create(octx, admin.Org.ID, "Audit server", "", "", []string{c.ID}, admin.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	var key struct {
		Secret string `json:"secret"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/api-keys", map[string]any{"name": "mcp"}, &key); code != 200 && code != 201 {
		t.Fatalf("create key: %d", code)
	}

	h.callTool(t, srv.ID, key.Secret, "fake_get_item", map[string]any{"id": "42"})

	events := h.auditEvents(t, ctx, admin.Org.ID)
	var call *audit.Record
	for i, e := range events {
		if e.Action == "tool.invoke" {
			call = &events[i]
			break
		}
	}
	if call == nil {
		t.Fatalf("the tool call is not in the audit trail; it holds %v", actions(events))
	}
	if call.TargetDisplay != "fake_get_item" {
		t.Errorf("the tool call names %q, expected fake_get_item", call.TargetDisplay)
	}
	if call.Outcome != audit.Success {
		t.Errorf("the tool call was recorded as %q", call.Outcome)
	}
	// The default policy keeps the shape of the arguments and not their
	// values, so the id the caller passed must not appear.
	if payload, ok := call.Payload.(map[string]any); ok {
		if in, ok := payload["input"].(map[string]any); ok {
			if in["id"] == "42" {
				t.Error("the default payload policy stored the argument's value, not its shape")
			}
		}
	}
}

// --- helpers ---------------------------------------------------------------

// auditEvents flushes the writer and reads the organisation's stream.
func (h *harness) auditEvents(t *testing.T, ctx context.Context, orgID string) []audit.Record {
	t.Helper()
	if err := h.deps.Audit.Flush(ctx); err != nil {
		t.Fatalf("waiting for the audit writer: %v", err)
	}
	events, err := h.deps.AuditReader.List(ctx, audit.Query{OrgID: orgID, Limit: 200})
	if err != nil {
		t.Fatalf("reading the audit trail: %v", err)
	}
	return events
}

func actions(events []audit.Record) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Action)
	}
	return out
}

// containsSecret looks for a literal secret anywhere in an event's own
// fields, which is the cheapest way to catch a credential that leaked into
// a diff or a payload.
func containsSecret(e audit.Record, secret string) bool {
	if secret == "" {
		return false
	}
	for _, v := range []any{e.Diff, e.Payload, e.Meta} {
		if v == nil {
			continue
		}
		if found(v, secret) {
			return true
		}
	}
	return false
}

func found(v any, needle string) bool {
	switch x := v.(type) {
	case string:
		return x == needle
	case map[string]any:
		for _, e := range x {
			if found(e, needle) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if found(e, needle) {
				return true
			}
		}
	}
	return false
}

// callTool drives one tool call through the MCP endpoint with an API key,
// which is the path a real client takes.
func (h *harness) callTool(t *testing.T, serverID, key, tool string, args map[string]any) {
	t.Helper()
	ctx := context.Background()
	transport := &sdk.StreamableClientTransport{
		Endpoint:   h.url + "/mcp/" + serverID,
		HTTPClient: &http.Client{Transport: &keyRoundTripper{key: key, base: h.client.Transport}},
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "audit-e2e", Version: "1"}, nil)
	sess, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connecting to the MCP endpoint: %v", err)
	}
	defer func() { _ = sess.Close() }()
	res, err := sess.CallTool(ctx, &sdk.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("calling %s: %v", tool, err)
	}
	if res.IsError {
		t.Fatalf("calling %s returned an error result: %+v", tool, res.Content)
	}
}
