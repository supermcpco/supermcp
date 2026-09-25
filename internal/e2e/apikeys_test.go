package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// TestAPIKeyRotation rotates a key through the admin API and then presents
// both keys to the MCP endpoint: the old one keeps working for the grace
// period and stops after it, the new one works, and the audit trail records
// the rotation without either secret.
func TestAPIKeyRotation(t *testing.T) {
	h := start(t)
	upstream, _ := fakeUpstream(t)
	ctx := context.Background()
	admin := h.register(t, "E2E rotation")
	octx := tenant.WithOrg(ctx, admin.Org.ID)
	t.Cleanup(func() {
		_ = h.db.Bypass(ctx, "e2e cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, admin.Org.ID)
			return err
		})
	})

	c, err := h.connectors.Create(octx, admin.Org.ID, testConnector(t, upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := h.servers.Create(octx, admin.Org.ID, "Rotation server", "", "", []string{c.ID}, admin.User.ID)
	if err != nil {
		t.Fatal(err)
	}

	var old struct {
		Key struct {
			ID string `json:"id"`
		} `json:"key"`
		Secret string `json:"secret"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/api-keys", map[string]any{"name": "rotating"}, &old); code != http.StatusOK {
		t.Fatalf("create key: %d", code)
	}

	// Out-of-range grace is refused before anything changes.
	for _, grace := range []int{-1, 7*24*3600 + 1} {
		if code := h.do(t, http.MethodPost, "/api/v1/api-keys/"+old.Key.ID+"/rotate", map[string]any{"graceSeconds": grace}, nil); code != http.StatusUnprocessableEntity {
			t.Errorf("grace %d: got %d, want 422", grace, code)
		}
	}

	var rot struct {
		Key struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Prefix string `json:"prefix"`
		} `json:"key"`
		Secret            string    `json:"secret"`
		PreviousKeyID     string    `json:"previousKeyId"`
		PreviousExpiresAt time.Time `json:"previousExpiresAt"`
	}
	before := time.Now()
	if code := h.do(t, http.MethodPost, "/api/v1/api-keys/"+old.Key.ID+"/rotate", map[string]any{"graceSeconds": 3600}, &rot); code != http.StatusOK {
		t.Fatalf("rotate: %d", code)
	}
	if rot.Secret == "" || rot.Secret == old.Secret || rot.Key.ID == old.Key.ID || rot.Key.Name != "rotating" || rot.PreviousKeyID != old.Key.ID {
		t.Fatalf("rotation reply: %+v", rot)
	}
	if d := rot.PreviousExpiresAt.Sub(before.Add(time.Hour)); d < -5*time.Second || d > 5*time.Second {
		t.Errorf("old key stops at %v, want about an hour from now", rot.PreviousExpiresAt)
	}

	// Inside the grace period both keys work.
	if code := h.mcpInitialize(t, srv.ID, old.Secret); code != http.StatusOK {
		t.Errorf("old key inside grace: %d", code)
	}
	if code := h.mcpInitialize(t, srv.ID, rot.Secret); code != http.StatusOK {
		t.Errorf("new key: %d", code)
	}

	// A second rotation of the same key is refused.
	if code := h.do(t, http.MethodPost, "/api/v1/api-keys/"+old.Key.ID+"/rotate", map[string]any{"graceSeconds": 0}, nil); code != http.StatusConflict {
		t.Errorf("second rotation: got %d, want 409", code)
	}

	// Move the end of the grace period into the past: the old key stops,
	// the new one carries on.
	err = h.db.Tx(octx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE api_keys SET expires_at = now() - interval '1 second' WHERE id = $1`, old.Key.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if code := h.mcpInitialize(t, srv.ID, old.Secret); code != http.StatusUnauthorized {
		t.Errorf("old key after grace: got %d, want 401", code)
	}
	if code := h.mcpInitialize(t, srv.ID, rot.Secret); code != http.StatusOK {
		t.Errorf("new key after the old one lapsed: %d", code)
	}

	// The rotation is audited, against the old key, naming the
	// replacement, and neither secret is in it.
	events := h.auditEvents(t, ctx, admin.Org.ID)
	found := false
	for _, e := range events {
		if containsSecret(e, old.Secret) || containsSecret(e, rot.Secret) {
			t.Fatalf("the audit event %q carries an API key secret", e.Action)
		}
		if e.Action != "apikey.rotate" || e.Outcome != audit.Success {
			continue
		}
		found = true
		if e.TargetID != old.Key.ID {
			t.Errorf("the rotation targets %q, want the old key %q", e.TargetID, old.Key.ID)
		}
		if e.Meta["replacementId"] != rot.Key.ID {
			t.Errorf("the rotation does not name the replacement: %v", e.Meta)
		}
		if e.ActorID != admin.User.ID {
			t.Errorf("the rotation names actor %q, want %q", e.ActorID, admin.User.ID)
		}
	}
	if !found {
		t.Fatalf("no apikey.rotate event; the trail holds %v", actions(events))
	}
}

// mcpInitialize opens an MCP session with key and returns the status.
func (h *harness) mcpInitialize(t *testing.T, serverID, key string) int {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"rotation-e2e","version":"1"}}}`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.url+"/mcp/"+serverID, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// Revoking a key that is not there, or not any more, is a 404, not an
// internal error.
func TestAPIKeyRevokeMissing(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	admin := h.register(t, "E2E revoke")
	t.Cleanup(func() {
		_ = h.db.Bypass(ctx, "e2e cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, admin.Org.ID)
			return err
		})
	})
	if code := h.do(t, http.MethodDelete, "/api/v1/api-keys/no-such-key", nil, nil); code != http.StatusNotFound {
		t.Errorf("revoke unknown key: %d, want 404", code)
	}
	var k struct {
		Key struct {
			ID string `json:"id"`
		} `json:"key"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/api-keys", map[string]any{"name": "once"}, &k); code != http.StatusOK {
		t.Fatalf("create key: %d", code)
	}
	if code := h.do(t, http.MethodDelete, "/api/v1/api-keys/"+k.Key.ID, nil, nil); code >= 300 {
		t.Fatalf("revoke: %d", code)
	}
	if code := h.do(t, http.MethodDelete, "/api/v1/api-keys/"+k.Key.ID, nil, nil); code != http.StatusNotFound {
		t.Errorf("revoke twice: %d, want 404", code)
	}
}
