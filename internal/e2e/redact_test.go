package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestConnectorSecretsRedacted stores literal secrets in a connector's
// auth and transport, the state a provider-rotated literal refresh token
// or an imported document can leave behind, and checks that no API
// response and no audit event repeats them: the connector itself, the
// list, the re-sync preview, the revision history and the audit trail.
// Restoring a revision still puts the real values back, because it reads
// the stored snapshot, not the redacted one.
func TestConnectorSecretsRedacted(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	admin := h.register(t, "E2E connector redaction")

	const (
		refresh    = "literal-refresh-token-5f1e"
		secret     = "literal-client-secret-93ab"
		dbPassword = "literal-db-password-77c2"
		headerKey  = "literal-header-key-1d0e"
	)
	secrets := []string{refresh, secret, dbPassword, headerKey}

	var installed connectorView
	if code := h.do(t, http.MethodPost, "/api/v1/connectors/install", map[string]any{"slug": "ghost",
		"credentials": map[string]string{"GHOST_ADMIN_API_URL": "https://ghost.example", "GHOST_ADMIN_JWT": "not-a-real-token"}}, &installed); code != 200 {
		t.Fatalf("install: %d", code)
	}
	auth := map[string]any{"type": "oauth2", "grant": "refresh_token", "clientId": "client-1",
		"clientSecret": secret, "refreshToken": refresh, "tokenUrl": "https://auth.example/token",
		"extraHeaders": map[string]any{"X-Api-Key": headerKey}}
	transport := map[string]any{"type": "http", "baseUrl": "https://svc:" + dbPassword + "@api.example/v1"}
	authJSON, _ := json.Marshal(auth)
	transportJSON, _ := json.Marshal(transport)
	// An older catalog hash makes the re-sync preview compare auth and
	// transport with the bundled adapter.
	h.bypass(t, execSQL(`UPDATE connectors SET auth = $2, transport = $3, catalog_hash = $4 WHERE id = $1`,
		installed.ID, authJSON, transportJSON, ghostV120))

	leaks := func(label string, raw []byte) {
		t.Helper()
		for _, s := range secrets {
			if strings.Contains(string(raw), s) {
				t.Errorf("%s repeats the secret %q: %s", label, s, raw)
			}
		}
	}
	get := func(label, path string) json.RawMessage {
		t.Helper()
		var raw json.RawMessage
		if code := h.do(t, http.MethodGet, path, nil, &raw); code != http.StatusOK {
			t.Fatalf("%s: %d %s", label, code, raw)
		}
		leaks(label, raw)
		return raw
	}

	var one struct {
		Auth      map[string]any `json:"auth"`
		Transport map[string]any `json:"transport"`
	}
	if err := json.Unmarshal(get("the connector", "/api/v1/connectors/"+installed.ID), &one); err != nil {
		t.Fatal(err)
	}
	if one.Auth["refreshToken"] != "***" || one.Auth["clientSecret"] != "***" || one.Auth["clientId"] != "client-1" {
		t.Errorf("auth is %v, want the secrets as *** and the rest as stored", one.Auth)
	}
	if one.Transport["baseUrl"] != "https://svc:***@api.example/v1" {
		t.Errorf("baseUrl is %v, want the password in it redacted", one.Transport["baseUrl"])
	}
	get("the connector list", "/api/v1/connectors")
	var plan struct {
		NotApplied []struct {
			Field  string `json:"field"`
			Before string `json:"before"`
		} `json:"notApplied"`
	}
	if err := json.Unmarshal(get("the re-sync preview", "/api/v1/connectors/"+installed.ID+"/resync"), &plan); err != nil {
		t.Fatal(err)
	}
	fields := map[string]bool{}
	for _, f := range plan.NotApplied {
		fields[f.Field] = true
	}
	if !fields["auth"] || !fields["transport"] {
		t.Errorf("the preview does not report auth and transport as different: %+v", plan.NotApplied)
	}

	// An edit records a revision whose snapshot holds the whole connector.
	var updated json.RawMessage
	if code := h.do(t, http.MethodPatch, "/api/v1/connectors/"+installed.ID, map[string]any{"name": "Ghost renamed"}, &updated); code != http.StatusOK {
		t.Fatalf("update: %d", code)
	}
	leaks("the update response", updated)
	var revs struct {
		Revisions []struct {
			Revision int `json:"revision"`
		} `json:"revisions"`
	}
	if err := json.Unmarshal(get("the revision list", "/api/v1/connectors/"+installed.ID+"/revisions"), &revs); err != nil {
		t.Fatal(err)
	}
	if len(revs.Revisions) == 0 {
		t.Fatal("the edit recorded no revision")
	}
	latest := strconv.Itoa(revs.Revisions[0].Revision)
	get("the latest revision", "/api/v1/connectors/"+installed.ID+"/revisions/"+latest)

	// Restoring reads the stored snapshot, so the real values survive.
	var restored json.RawMessage
	if code := h.do(t, http.MethodPost, "/api/v1/connectors/"+installed.ID+"/revisions/"+latest+"/restore", nil, &restored); code != http.StatusOK {
		t.Fatalf("restore: %d %s", code, restored)
	}
	leaks("the restore response", restored)
	var storedAuth, storedTransport string
	h.bypass(t, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT auth->>'refreshToken', transport->>'baseUrl' FROM connectors WHERE id = $1`, installed.ID).
			Scan(&storedAuth, &storedTransport)
	})
	if storedAuth != refresh || !strings.Contains(storedTransport, dbPassword) {
		t.Errorf("after a restore the connector holds refreshToken %q and baseUrl %q; the redaction reached the store", storedAuth, storedTransport)
	}

	// Deleting records the whole connector as it was.
	if code := h.do(t, http.MethodDelete, "/api/v1/connectors/"+installed.ID, nil, nil); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("delete: %d", code)
	}
	for _, e := range h.auditEvents(t, ctx, admin.Org.ID) {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		leaks("audit event "+e.Action, raw)
	}
}
