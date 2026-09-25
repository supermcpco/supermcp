package e2e

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/governance"
	"github.com/supermcpco/supermcp/internal/invalidation"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// The data-loss policies, the approval policies and the sign-in providers
// keep a history like a connector does: every change is a revision with
// its diff, and a restore puts an earlier version back through the path
// an edit takes, so it is recorded, audited and seen by every replica.

// policyRevision is one entry of a history as these tests read it.
type policyRevision struct {
	Revision int            `json:"revision"`
	Action   string         `json:"action"`
	ActorID  string         `json:"actorId"`
	Diff     *audit.Diff    `json:"diff"`
	Snapshot map[string]any `json:"snapshot"`
}

type policyRevisions struct {
	Revisions []policyRevision `json:"revisions"`
}

func (h *harness) history(t *testing.T, path string) []policyRevision {
	t.Helper()
	var out policyRevisions
	if code := h.do(t, http.MethodGet, path+"/revisions", nil, &out); code != http.StatusOK {
		t.Fatalf("GET %s/revisions: %d", path, code)
	}
	return out.Revisions
}

// changed reports whether a revision's diff moved one field from one value
// to another.
func changed(r policyRevision, field string, from, to any) bool {
	if r.Diff == nil {
		return false
	}
	return r.Diff.Before[field] == from && r.Diff.After[field] == to
}

// restoreEvent finds the audit record of a restore of one revision.
func (h *harness) restoreEvent(t *testing.T, orgID, kind, id string, revision int) *audit.Record {
	t.Helper()
	for _, e := range h.auditEvents(t, context.Background(), orgID) {
		if e.Action != kind+".revision.restore" || e.TargetID != id || e.Outcome != audit.Success {
			continue
		}
		if n, ok := e.Meta["revision"].(float64); ok && int(n) == revision {
			return &e
		}
	}
	return nil
}

// listen runs an invalidation listener for the tool-call path's policy
// reader, as the process does for each replica, and returns once it is up.
func (h *harness) listen(t *testing.T) {
	t.Helper()
	l := invalidation.NewListener(invalidation.Options{URL: h.dsn, Prober: h.db.Maint,
		ApplicationName: "e2e-" + newID()[:8], MinBackoff: 20 * time.Millisecond, MaxBackoff: 200 * time.Millisecond})
	l.Register(invalidation.KindDLP, h.dlp)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = l.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	eventually(t, 10*time.Second, "the listener connects", l.Connected)
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.After(within)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("%s: not within %s", what, within)
		case <-tick.C:
		}
	}
}

// callText makes one tool call over MCP and returns what the model would
// be shown, and whether it was an error.
func (h *harness) callText(t *testing.T, serverID, key, tool string, args map[string]any) (string, bool) {
	t.Helper()
	ctx := context.Background()
	transport := &sdk.StreamableClientTransport{
		Endpoint:   h.url + "/mcp/" + serverID,
		HTTPClient: &http.Client{Transport: &keyRoundTripper{key: key, base: h.client.Transport}},
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "revisions-e2e", Version: "1"}, nil)
	sess, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connecting to the MCP endpoint: %v", err)
	}
	defer func() { _ = sess.Close() }()
	res, err := sess.CallTool(ctx, &sdk.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("calling %s: %v", tool, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

// policySetup is a workspace with one connector served by one MCP server,
// and a key to call it with.
type policySetup struct {
	h      *harness
	admin  registered
	orgID  string
	conn   string
	server string
	key    string
}

func newPolicySetup(t *testing.T, name string) *policySetup {
	t.Helper()
	h := start(t)
	upstream, _ := fakeUpstream(t)
	admin := h.register(t, name)
	s := &policySetup{h: h, admin: admin, orgID: admin.Org.ID}
	octx := tenant.WithOrg(context.Background(), s.orgID)
	c, err := h.connectors.Create(octx, s.orgID, testConnector(t, upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := h.servers.Create(octx, s.orgID, "Revisions server", "", "", []string{c.ID}, admin.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	var key struct {
		Secret string `json:"secret"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/api-keys", map[string]any{"name": "revisions"}, &key); code != http.StatusOK {
		t.Fatalf("create key: %d", code)
	}
	s.conn, s.server, s.key = c.ID, srv.ID, key.Secret
	t.Cleanup(func() {
		ctx := context.Background()
		_ = h.db.Bypass(ctx, "e2e cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM tool_invocations WHERE organization_id = $1;
				DELETE FROM organizations WHERE id = $1`, s.orgID)
			return err
		})
	})
	return s
}

// TestDLPPolicyRevisions: two edits leave two revisions with their diffs;
// a restore puts the rule back, is recorded and audited, and changes what
// the next call on another replica does; a deleted rule comes back under
// its old id.
func TestDLPPolicyRevisions(t *testing.T) {
	s := newPolicySetup(t, "E2E DLP revisions")
	h := s.h
	h.listen(t)
	const address = "alice@example.com"
	call := func() (string, bool) {
		return h.callText(t, s.server, s.key, "fake_get_item", map[string]any{"id": address})
	}

	rule := func(action string) map[string]any {
		return map[string]any{"name": "Addresses", "connectorId": s.conn, "scan": "result",
			"detectors": []string{"email"}, "action": action, "enabled": true}
	}
	var created struct {
		ID     string `json:"id"`
		Action string `json:"action"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/dlp/policies", rule("allow"), &created); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	path := "/api/v1/dlp/policies/" + created.ID
	if code := h.do(t, http.MethodPut, path, rule("mask"), nil); code != http.StatusOK {
		t.Fatalf("first edit: %d", code)
	}
	if text, isErr := call(); isErr || strings.Contains(text, address) {
		t.Fatalf("a masking rule let the address through: %v %s", isErr, text)
	}
	if code := h.do(t, http.MethodPut, path, rule("refuse"), nil); code != http.StatusOK {
		t.Fatalf("second edit: %d", code)
	}
	// The tool-call path's cache now holds the refusing rule.
	eventually(t, 10*time.Second, "the tool-call path refuses", func() bool {
		_, isErr := call()
		return isErr
	})

	revs := h.history(t, path)
	if len(revs) != 3 || revs[0].Action != "update" || revs[1].Action != "update" || revs[2].Action != "create" {
		t.Fatalf("history after a create and two edits: %+v", revs)
	}
	if !changed(revs[1], "action", "allow", "mask") || !changed(revs[0], "action", "mask", "refuse") {
		t.Errorf("the diffs do not say what the edits changed: %+v / %+v", revs[1].Diff, revs[0].Diff)
	}
	if revs[0].ActorID != s.admin.User.ID {
		t.Errorf("the edit is recorded as made by %q, want %q", revs[0].ActorID, s.admin.User.ID)
	}

	// Put the masking rule back.
	var restored struct {
		ID     string `json:"id"`
		Action string `json:"action"`
	}
	if code := h.do(t, http.MethodPost, path+"/revisions/2/restore", nil, &restored); code != http.StatusOK {
		t.Fatalf("restore: %d", code)
	}
	if restored.ID != created.ID || restored.Action != "mask" {
		t.Fatalf("restore answered %+v, want the masking rule back", restored)
	}
	// Another replica's cache hears of it from the database, not after
	// its thirty seconds are up.
	eventually(t, 5*time.Second, "the tool-call path sees the restored rule", func() bool {
		got, found, err := h.dlp.Resolve(context.Background(), s.orgID, s.conn, "")
		return err == nil && found && got.Action == "mask"
	})
	if text, isErr := call(); isErr || strings.Contains(text, address) {
		t.Errorf("after the restore the next call should be masked, not refused: %v %s", isErr, text)
	}
	revs = h.history(t, path)
	if len(revs) != 4 || revs[0].Action != "update" || !changed(revs[0], "action", "refuse", "mask") {
		t.Errorf("the restore is not recorded as a further change: %+v", revs)
	}
	if h.restoreEvent(t, s.orgID, "dlp_policy", created.ID, 2) == nil {
		t.Error("the restore is not on the audit trail")
	}

	// A deleted rule keeps its history, and comes back from it.
	if code := h.do(t, http.MethodDelete, path, nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	revs = h.history(t, path)
	if len(revs) != 5 || revs[0].Action != "delete" {
		t.Fatalf("history after the delete: %+v", revs)
	}
	eventually(t, 5*time.Second, "the tool-call path drops the deleted rule", func() bool {
		_, found, err := h.dlp.Resolve(context.Background(), s.orgID, s.conn, "")
		return err == nil && !found
	})
	if code := h.do(t, http.MethodPost, path+"/revisions/3/restore", nil, &restored); code != http.StatusOK {
		t.Fatalf("restoring a deleted rule: %d", code)
	}
	if restored.ID != created.ID || restored.Action != "refuse" {
		t.Errorf("the deleted rule came back as %+v, want its id and the refusing version", restored)
	}
	if code := h.do(t, http.MethodGet, path, nil, nil); code != http.StatusOK {
		t.Errorf("the restored rule cannot be read: %d", code)
	}
	if revs = h.history(t, path); revs[0].Action != "create" {
		t.Errorf("recreating a deleted rule is recorded as %q, want create", revs[0].Action)
	}
	eventually(t, 5*time.Second, "the tool-call path sees the recreated rule", func() bool {
		got, found, err := h.dlp.Resolve(context.Background(), s.orgID, s.conn, "")
		return err == nil && found && got.Action == "refuse"
	})

	if code := h.do(t, http.MethodGet, path+"/revisions", nil, nil); code != http.StatusOK {
		t.Errorf("reading the history: %d, want 200", code)
	}
}

// TestPolicyRestoreNeedsTheEditPermission: revisions:rollback alone does
// not let somebody change what a tool call may carry, which calls need a
// person, or how people sign in. Each restore also asks for the permission
// that edits the thing, and it asks before it looks anything up.
func TestPolicyRestoreNeedsTheEditPermission(t *testing.T) {
	h := start(t)
	admin := h.register(t, "E2E rollback only")
	ctx := context.Background()
	t.Cleanup(func() {
		_ = h.db.Bypass(ctx, "e2e cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, admin.Org.ID)
			return err
		})
	})
	var role struct {
		ID string `json:"id"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/roles", map[string]any{"name": "Rollback only",
		"permissions": []string{"org:read", "connectors:read", "revisions:rollback"}}, &role); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("create role: %d", code)
	}
	m := h.member(t, admin.Org.ID, role.ID)
	for _, c := range []struct{ kind, path string }{
		{"dlp policy", "/api/v1/dlp/policies/"},
		{"approval policy", "/api/v1/approval-policies/"},
		{"OIDC provider", "/api/v1/idps/"},
		{"SAML provider", "/api/v1/saml-providers/"},
	} {
		id := newID()
		if code := m.do(t, http.MethodPost, c.path+id+"/revisions/1/restore", nil, nil); code != http.StatusForbidden {
			t.Errorf("a %s restore with revisions:rollback alone: %d, want 403", c.kind, code)
		}
		// The owner holds both, so the same request gets as far as the
		// history, which has no such revision.
		if code := h.do(t, http.MethodPost, c.path+id+"/revisions/1/restore", nil, nil); code != http.StatusNotFound {
			t.Errorf("a %s restore by the owner: %d, want 404", c.kind, code)
		}
	}
}

// TestApprovalPolicyRevisions: the same for the rules that decide which
// calls need a person. They are read from the table on every call rather
// than cached, so a restore governs the next call as soon as it commits.
func TestApprovalPolicyRevisions(t *testing.T) {
	s := newPolicySetup(t, "E2E approval revisions")
	h := s.h
	ctx := context.Background()
	rule := func(name, effect string) map[string]any {
		return map[string]any{"name": name, "trigger": "tool", "toolName": "fake_get_item", "effect": effect}
	}
	var created struct {
		ID string `json:"id"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/approval-policies", rule("Ask first", "require"), &created); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	path := "/api/v1/approval-policies/" + created.ID
	if code := h.do(t, http.MethodPut, path, rule("Ask first", "allow"), nil); code != http.StatusOK {
		t.Fatalf("first edit: %d", code)
	}
	if code := h.do(t, http.MethodPut, path, rule("Never ask", "allow"), nil); code != http.StatusOK {
		t.Fatalf("second edit: %d", code)
	}
	revs := h.history(t, path)
	if len(revs) != 3 || revs[2].Action != "create" {
		t.Fatalf("history after a create and two edits: %+v", revs)
	}
	if !changed(revs[1], "effect", "require", "allow") || !changed(revs[0], "name", "Ask first", "Never ask") {
		t.Errorf("the diffs do not say what the edits changed: %+v / %+v", revs[1].Diff, revs[0].Diff)
	}

	governing := func() string {
		svc := governance.NewApprovals(h.db, nil, newID)
		p, err := svc.Governing(ctx, governance.CallRef{OrgID: s.orgID, ServerID: s.server, ConnectorID: s.conn,
			ToolName: "fake_get_item"})
		if err != nil {
			t.Fatal(err)
		}
		if p == nil {
			return ""
		}
		return string(p.Effect)
	}
	if got := governing(); got != "allow" {
		t.Fatalf("before the restore the call is governed by %q", got)
	}
	var restored struct {
		Name   string `json:"name"`
		Effect string `json:"effect"`
	}
	if code := h.do(t, http.MethodPost, path+"/revisions/1/restore", nil, &restored); code != http.StatusOK {
		t.Fatalf("restore: %d", code)
	}
	if restored.Name != "Ask first" || restored.Effect != "require" {
		t.Errorf("restore answered %+v", restored)
	}
	if got := governing(); got != "require" {
		t.Errorf("after the restore the call is governed by %q, want require", got)
	}
	// The next call is held for a person.
	if text, isErr := h.callText(t, s.server, s.key, "fake_get_item", map[string]any{"id": "1"}); !isErr || !strings.Contains(strings.ToLower(text), "approv") {
		t.Errorf("after the restore the call ran without asking: %v %s", isErr, text)
	}
	revs = h.history(t, path)
	if len(revs) != 4 || revs[0].Action != "update" || !changed(revs[0], "effect", "allow", "require") {
		t.Errorf("the restore is not recorded as a further change: %+v", revs)
	}
	if h.restoreEvent(t, s.orgID, "approval_policy", created.ID, 1) == nil {
		t.Error("the restore is not on the audit trail")
	}

	if code := h.do(t, http.MethodDelete, path, nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if code := h.do(t, http.MethodPost, path+"/revisions/4/restore", nil, &restored); code != http.StatusOK {
		t.Fatalf("restoring a deleted rule: %d", code)
	}
	if got := governing(); got != "require" {
		t.Errorf("the recreated rule does not govern the call: %q", got)
	}
}

// TestIdentityProviderRevisions: a provider's history never holds its
// client secret, and a restore keeps the secret stored when it runs.
func TestIdentityProviderRevisions(t *testing.T) {
	h := start(t)
	admin := h.register(t, "E2E identity provider revisions")
	ctx := context.Background()
	t.Cleanup(func() {
		_ = h.db.Bypass(ctx, "e2e cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, admin.Org.ID)
			return err
		})
	})
	const first, second = "first-client-secret-value", "second-client-secret-value"
	provider := func(name, secret string, domains []string) map[string]any {
		body := map[string]any{"name": name, "preset": "generic", "issuer": "https://idp.example.test",
			"clientId": "supermcp", "allowedDomains": domains, "enabled": true, "jitProvisioning": true,
			"authorizationEndpoint": "https://idp.example.test/authorize", "tokenEndpoint": "https://idp.example.test/token"}
		if secret != "" {
			body["clientSecret"] = secret
		}
		return body
	}
	var created struct {
		ID string `json:"id"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/idps", provider("Company SSO", first, []string{"example.com"}), &created); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	path := "/api/v1/idps/" + created.ID
	if code := h.do(t, http.MethodPut, path, provider("Company SSO", "", []string{"example.com", "example.org"}), nil); code != http.StatusOK {
		t.Fatalf("first edit: %d", code)
	}
	if code := h.do(t, http.MethodPut, path, provider("Renamed SSO", second, []string{"example.org"}), nil); code != http.StatusOK {
		t.Fatalf("second edit: %d", code)
	}
	revs := h.history(t, path)
	if len(revs) != 3 || revs[2].Action != "create" || !changed(revs[0], "name", "Company SSO", "Renamed SSO") {
		t.Fatalf("history after a create and two edits: %+v", revs)
	}
	if revs[1].Diff == nil || revs[1].Diff.After["allowedDomains"] == nil {
		t.Errorf("the first edit's diff does not show the domains: %+v", revs[1].Diff)
	}

	// Neither secret is anywhere in the history, and the endpoints are
	// there to be put back rather than digested.
	var one policyRevision
	if code := h.do(t, http.MethodGet, path+"/revisions/1", nil, &one); code != http.StatusOK {
		t.Fatalf("read revision: %d", code)
	}
	for _, r := range append(revs, one) {
		for _, v := range []any{r.Snapshot, diffMaps(r.Diff)} {
			if found(v, first) || found(v, second) {
				t.Fatalf("revision %d holds a client secret", r.Revision)
			}
		}
	}
	if ep, _ := one.Snapshot["endpoints"].(map[string]any); ep["token"] != "https://idp.example.test/token" {
		t.Errorf("the snapshot does not keep the token endpoint as written: %+v", one.Snapshot)
	}

	sealed := func() []byte {
		var enc []byte
		if err := h.db.Bypass(ctx, "e2e read secret", func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT client_secret_enc FROM identity_providers WHERE id = $1`, created.ID).Scan(&enc)
		}); err != nil {
			t.Fatal(err)
		}
		return enc
	}
	before := sealed()

	var restored struct {
		Name             string   `json:"name"`
		AllowedDomains   []string `json:"allowedDomains"`
		TokenEndpoint    string   `json:"tokenEndpoint"`
		ClientSecretKept bool     `json:"clientSecretKept"`
	}
	if code := h.do(t, http.MethodPost, path+"/revisions/1/restore", nil, &restored); code != http.StatusOK {
		t.Fatalf("restore: %d", code)
	}
	if restored.Name != "Company SSO" || len(restored.AllowedDomains) != 1 || restored.AllowedDomains[0] != "example.com" ||
		restored.TokenEndpoint != "https://idp.example.test/token" || !restored.ClientSecretKept {
		t.Errorf("restore answered %+v", restored)
	}
	if !bytes.Equal(sealed(), before) {
		t.Error("the restore changed the stored client secret")
	}
	revs = h.history(t, path)
	if len(revs) != 4 || !changed(revs[0], "name", "Renamed SSO", "Company SSO") {
		t.Errorf("the restore is not recorded as a further change: %+v", revs)
	}
	if h.restoreEvent(t, admin.Org.ID, "identity_provider", created.ID, 1) == nil {
		t.Error("the restore is not on the audit trail")
	}

	// A deleted provider keeps its history but cannot come back from it.
	if code := h.do(t, http.MethodDelete, path, nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if revs = h.history(t, path); len(revs) != 5 || revs[0].Action != "delete" {
		t.Fatalf("history after the delete: %+v", revs)
	}
	var refused refusal
	if code := h.do(t, http.MethodPost, path+"/revisions/1/restore", nil, &refused); code != http.StatusNotFound ||
		!strings.Contains(refused.Detail, "client secret") {
		t.Errorf("restoring a deleted provider: %d %+v, want 404 naming the secret", code, refused)
	}
}

func diffMaps(d *audit.Diff) any {
	if d == nil {
		return nil
	}
	return map[string]any{"before": d.Before, "after": d.After}
}

// TestIdentityProviderRestoreToAnotherIssuerNeedsASecret: the stored
// client secret is only ever sent where it was configured to go. A
// restore, or an edit, that points the provider at another issuer or at an
// endpoint on another host is refused unless it brings a secret of its
// own.
func TestIdentityProviderRestoreToAnotherIssuerNeedsASecret(t *testing.T) {
	h := start(t)
	admin := h.register(t, "E2E repointed provider")
	ctx := context.Background()
	t.Cleanup(func() {
		_ = h.db.Bypass(ctx, "e2e cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, admin.Org.ID)
			return err
		})
	})
	provider := func(host, secret string) map[string]any {
		body := map[string]any{"name": "Company SSO", "preset": "generic", "issuer": "https://" + host,
			"clientId": "supermcp", "enabled": true, "jitProvisioning": true,
			"authorizationEndpoint": "https://" + host + "/authorize", "tokenEndpoint": "https://" + host + "/token"}
		if secret != "" {
			body["clientSecret"] = secret
		}
		return body
	}
	var created struct {
		ID string `json:"id"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/idps", provider("old-idp.example.test", "old-secret-value"), &created); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	path := "/api/v1/idps/" + created.ID
	sealed := func() []byte {
		var enc []byte
		if err := h.db.Bypass(ctx, "e2e read secret", func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT client_secret_enc FROM identity_providers WHERE id = $1`, created.ID).Scan(&enc)
		}); err != nil {
			t.Fatal(err)
		}
		return enc
	}

	// An edit to a new issuer without a secret is refused; with one it
	// goes through.
	var refused refusal
	if code := h.do(t, http.MethodPut, path, provider("new-idp.example.test", ""), &refused); code != http.StatusUnprocessableEntity ||
		!strings.Contains(refused.Detail, "client secret") {
		t.Fatalf("repointing without a secret: %d %+v, want 422 naming the secret", code, refused)
	}
	// So is keeping the issuer but moving the token endpoint to another host.
	moved := provider("old-idp.example.test", "")
	moved["tokenEndpoint"] = "https://collector.example.test/token"
	if code := h.do(t, http.MethodPut, path, moved, nil); code != http.StatusUnprocessableEntity {
		t.Errorf("moving the token endpoint without a secret: %d, want 422", code)
	}
	if code := h.do(t, http.MethodPut, path, provider("new-idp.example.test", "new-secret-value"), nil); code != http.StatusOK {
		t.Fatalf("repointing with a secret: %d", code)
	}
	current := sealed()

	// Restoring the old issuer would send the new secret there.
	refused = refusal{}
	if code := h.do(t, http.MethodPost, path+"/revisions/1/restore", nil, &refused); code != http.StatusUnprocessableEntity ||
		!strings.Contains(refused.Detail, "client secret") {
		t.Fatalf("restoring another issuer without a secret: %d %+v, want 422 naming the secret", code, refused)
	}
	var now struct {
		Providers []struct {
			ID     string `json:"id"`
			Issuer string `json:"issuer"`
		} `json:"providers"`
	}
	h.do(t, http.MethodGet, "/api/v1/idps", nil, &now)
	if len(now.Providers) != 1 || now.Providers[0].Issuer != "https://new-idp.example.test" || !bytes.Equal(sealed(), current) {
		t.Errorf("a refused restore changed the provider: %+v", now.Providers)
	}
	if h.restoreEvent(t, admin.Org.ID, "identity_provider", created.ID, 1) != nil {
		t.Error("a refused restore is recorded as a success")
	}

	// With a secret for the old issuer it goes through, and the answer
	// says the stored secret was not kept.
	var restored struct {
		Issuer           string `json:"issuer"`
		ClientSecretKept bool   `json:"clientSecretKept"`
	}
	if code := h.do(t, http.MethodPost, path+"/revisions/1/restore", map[string]any{"clientSecret": "old-secret-again"}, &restored); code != http.StatusOK {
		t.Fatalf("restoring another issuer with a secret: %d", code)
	}
	if restored.Issuer != "https://old-idp.example.test" || restored.ClientSecretKept || bytes.Equal(sealed(), current) {
		t.Errorf("restore with a secret answered %+v", restored)
	}

	// The audit trail shows where sign-in was pointed, before and after:
	// the issuer, and the token endpoint the secret is sent to.
	shown := false
	for _, e := range h.auditEvents(t, ctx, admin.Org.ID) {
		if e.Action != "idp.update" || e.Outcome != audit.Success {
			continue
		}
		before, _ := e.Diff["before"].(map[string]any)
		after, _ := e.Diff["after"].(map[string]any)
		ep, _ := after["endpoints"].(map[string]any)
		if before["issuer"] == "https://new-idp.example.test" && after["issuer"] == "https://old-idp.example.test" &&
			ep["token"] == "https://old-idp.example.test/token" {
			shown = true
		}
	}
	if !shown {
		t.Error("no idp.update on the audit trail shows the issuer and token endpoint moving back")
	}
}
