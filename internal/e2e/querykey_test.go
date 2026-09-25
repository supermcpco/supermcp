package e2e

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/tenant"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// TestQueryKeyNeverRecorded fails a call on a connector whose API key
// travels in the query string, the way an upstream that is down fails it.
// net/http names the whole request URL in that error, key included, and
// the error is kept on the invocation row, in the audit event's meta
// (which the audit search indexes) and in the answer to the caller. None
// of them may hold the key.
func TestQueryKeyNeverRecorded(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	admin := h.register(t, "E2E query key")
	octx := tenant.WithOrg(ctx, admin.Org.ID)

	// A port nothing listens on: the call is refused at connect.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + l.Addr().String()
	_ = l.Close()

	// A parameter name the connector redaction does not recognise, so
	// only scrubbing the URL itself keeps the key out.
	const key = "qk-3f9a8e7d6c5b-e2e" // gitleaks:allow
	in := testConnector(t, closed)
	in.Auth = adapter.Auth{Type: adapter.AuthAPIKey, In: "query", Name: "access", Value: "{{env.FAKE_KEY}}"}
	in.Credentials = map[string]string{"FAKE_KEY": key}
	c, err := h.connectors.Create(octx, admin.Org.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := h.servers.Create(octx, admin.Org.ID, "Query key server", "", "", []string{c.ID}, admin.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	var mcpKey struct {
		Secret string `json:"secret"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/api-keys", map[string]any{"name": "mcp"}, &mcpKey); code != 200 && code != 201 {
		t.Fatalf("create key: %d", code)
	}

	transport := &sdk.StreamableClientTransport{
		Endpoint:   h.url + "/mcp/" + srv.ID,
		HTTPClient: &http.Client{Transport: &keyRoundTripper{key: mcpKey.Secret, base: h.client.Transport}},
	}
	sess, err := sdk.NewClient(&sdk.Implementation{Name: "query-key-e2e", Version: "1"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	res, err := sess.CallTool(ctx, &sdk.CallToolParams{Name: "fake_get_item", Arguments: map[string]any{"id": "42"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("a call to a closed port succeeded: %+v", res.Content)
	}
	answer, _ := json.Marshal(res.Content)
	if strings.Contains(string(answer), key) {
		t.Errorf("the caller was answered with the key: %s", answer)
	}

	var rowErr string
	h.bypass(t, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT error FROM tool_invocations WHERE organization_id = $1 AND tool_name = 'fake_get_item'`,
			admin.Org.ID).Scan(&rowErr)
	})
	if strings.Contains(rowErr, key) {
		t.Errorf("the invocation row keeps the key: %s", rowErr)
	}
	if !strings.Contains(rowErr, "refused") {
		t.Errorf("the invocation row no longer says why the call failed: %q", rowErr)
	}

	var call *audit.Record
	for _, e := range h.auditEvents(t, ctx, admin.Org.ID) {
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), key) {
			t.Errorf("the audit event %s keeps the key: %s", e.Action, raw)
		}
		if e.Action == "tool.invoke" {
			call = &e
		}
	}
	if call == nil || call.Meta["error"] == nil {
		t.Fatalf("the failed call left no audit event with an error: %+v", call)
	}

	for q, want := range map[string]int{key: 0, `"` + key + `"`: 0, "refused": 1} {
		found, err := h.deps.AuditReader.List(ctx, audit.Query{OrgID: admin.Org.ID, Search: q})
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != want {
			t.Errorf("searching the trail for %s found %d events, want %d", q, len(found), want)
		}
	}
}
