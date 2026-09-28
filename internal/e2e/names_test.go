package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
)

type namedSession struct {
	User *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"user"`
	Org *struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
		Name string `json:"name"`
	} `json:"organization"`
	Orgs []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"organizations"`
	Anonymous bool `json:"anonymous"`
}

func (h *harness) namedSession(t *testing.T) namedSession {
	t.Helper()
	var s namedSession
	if code := h.do(t, http.MethodGet, "/api/v1/auth/session", nil, &s); code != http.StatusOK {
		t.Fatalf("read session: %d", code)
	}
	return s
}

// storedNames reads names straight from the tables, past row-level
// security, so a check does not depend on the API it is checking.
func (h *harness) storedNames(t *testing.T, table string, ids ...string) map[string]string {
	t.Helper()
	ctx := context.Background()
	out := map[string]string{}
	if err := h.db.Bypass(ctx, "e2e read names", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, name FROM `+pgx.Identifier{table}.Sanitize()+` WHERE id = ANY($1)`, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, name string
			if err := rows.Scan(&id, &name); err != nil {
				return err
			}
			out[id] = name
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// renamed finds the successful rename event for a target and checks the
// names it records.
func renamed(t *testing.T, events []audit.Record, action, targetID, before, after string) {
	t.Helper()
	for _, e := range events {
		if e.Action != action || e.Outcome != audit.Success || e.TargetID != targetID {
			continue
		}
		b, _ := e.Diff["before"].(map[string]any)
		a, _ := e.Diff["after"].(map[string]any)
		if b["name"] != before || a["name"] != after {
			t.Errorf("%s records %v, want the name going from %q to %q", action, e.Diff, before, after)
		}
		return
	}
	t.Errorf("no %s event for %s; the trail holds %v", action, targetID, actions(events))
}

// TestRenameSelf changes the signed-in person's name, and only theirs,
// without ending the session.
func TestRenameSelf(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	owner := h.register(t, "E2E rename self")
	dropOrgs(t, h, owner.Org.ID)
	other := h.member(t, owner.Org.ID, "role_viewer")
	otherID, _ := other.whoAmI(t)
	otherBefore := h.storedNames(t, "users", otherID)[otherID]
	cookie := h.cookie

	var got namedSession
	if code := h.do(t, http.MethodPatch, "/api/v1/me", map[string]any{"name": "  Ada Lovelace \t"}, &got); code != http.StatusOK {
		t.Fatalf("rename yourself: %d", code)
	}
	if got.User == nil || got.User.ID != owner.User.ID || got.User.Name != "Ada Lovelace" {
		t.Errorf("the answer names %+v, want the trimmed new name", got.User)
	}
	if got.Org == nil || got.Org.ID != owner.Org.ID {
		t.Errorf("the answer is not the session: organization %+v", got.Org)
	}
	if h.cookie != cookie {
		t.Error("renaming yourself replaced the session cookie")
	}
	if s := h.namedSession(t); s.Anonymous || s.User == nil || s.User.Name != "Ada Lovelace" {
		t.Errorf("the session afterwards reads %+v", s)
	}
	if other.namedSession(t).Anonymous {
		t.Error("renaming yourself signed another member out")
	}
	if n := h.storedNames(t, "users", otherID)[otherID]; n != otherBefore {
		t.Errorf("another member's name went from %q to %q", otherBefore, n)
	}
	renamed(t, h.auditEvents(t, ctx, owner.Org.ID), "account.update", owner.User.ID, "", "Ada Lovelace")
}

// TestRenameSelfRefusals: a bad name, no credential, or a credential
// that is not a person's own session changes nothing.
func TestRenameSelfRefusals(t *testing.T) {
	h := start(t)
	owner := h.register(t, "E2E rename self refusals")
	dropOrgs(t, h, owner.Org.ID)
	if code := h.do(t, http.MethodPatch, "/api/v1/me", map[string]any{"name": "Grace"}, nil); code != http.StatusOK {
		t.Fatalf("rename yourself: %d", code)
	}

	for _, c := range []struct{ name, value string }{
		{"empty", ""},
		{"blank", "   "},
		{"too long", strings.Repeat("a", 121)},
		{"newline", "Grace\nHopper"},
		{"escape", "Grace\x1b[2J"},
		{"bidi override", "Grace\u202eyppoh"},
	} {
		var ref refusal
		if code := h.do(t, http.MethodPatch, "/api/v1/me", map[string]any{"name": c.value}, &ref); code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d, want 422", c.name, code)
		} else if len(ref.Errors) == 0 || ref.Errors[0].Location != "body.name" {
			t.Errorf("%s: the refusal points at %+v, want body.name", c.name, ref.Errors)
		}
	}
	if code := h.anonymous().do(t, http.MethodPatch, "/api/v1/me", map[string]any{"name": "Nobody"}, nil); code != http.StatusUnauthorized {
		t.Errorf("no credential: %d, want 401", code)
	}
	code, ref, key := h.createKey(t, "rename probe", nil)
	if code != http.StatusOK {
		t.Fatalf("create a key: %d %+v", code, ref)
	}
	if code := h.asKey(t, key, http.MethodPatch, "/api/v1/me", map[string]any{"name": "Key"}); code != http.StatusForbidden {
		t.Errorf("an API key: %d, want 403", code)
	}
	if n := h.storedNames(t, "users", owner.User.ID)[owner.User.ID]; n != "Grace" {
		t.Errorf("a refused rename left the name %q", n)
	}
	denied := false
	for _, e := range h.auditEvents(t, context.Background(), owner.Org.ID) {
		if e.Action == "account.update" && e.Outcome == audit.Denied && e.ActorKind == "api_key" {
			denied = true
		}
	}
	if !denied {
		t.Error("the API key's attempt is not in the trail as denied")
	}
}

// TestRenameSelfEveryWorkspace: the name is the person's, shown in every
// workspace they belong to, so every one of those trails records it.
func TestRenameSelfEveryWorkspace(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	owner := h.register(t, "E2E rename two orgs")
	m := h.member(t, owner.Org.ID, "role_viewer")
	var home struct {
		Orgs []struct{ ID string } `json:"organizations"`
	}
	if code := m.do(t, http.MethodGet, "/api/v1/auth/session", nil, &home); code != http.StatusOK || len(home.Orgs) != 2 {
		t.Fatalf("the member's session: %d %+v, want two workspaces", code, home)
	}
	mID, _ := m.whoAmI(t)
	var own string
	for _, o := range home.Orgs {
		if o.ID != owner.Org.ID {
			own = o.ID
		}
	}
	dropOrgs(t, h, owner.Org.ID, own)

	if code := m.do(t, http.MethodPatch, "/api/v1/me", map[string]any{"name": "Two Places"}, nil); code != http.StatusOK {
		t.Fatalf("rename: %d", code)
	}
	for _, orgID := range []string{owner.Org.ID, own} {
		renamed(t, h.auditEvents(t, ctx, orgID), "account.update", mID, "", "Two Places")
	}
}

// TestRenameSelfSCIMManaged: a person an identity provider provisions,
// in any of their workspaces, cannot rename themselves here.
func TestRenameSelfSCIMManaged(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	owner := h.register(t, "E2E rename scim")
	m := h.member(t, owner.Org.ID, "role_viewer")
	mID, _ := m.whoAmI(t)
	// Provisioned in the workspace the member did not select.
	if err := h.db.Bypass(ctx, "e2e scim member", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO scim_users (organization_id, user_id, user_name) VALUES ($1, $2, $3)`,
			owner.Org.ID, mID, newID())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var home struct {
		Orgs []struct{ ID string } `json:"organizations"`
	}
	m.do(t, http.MethodGet, "/api/v1/auth/session", nil, &home)
	var own string
	for _, o := range home.Orgs {
		if o.ID != owner.Org.ID {
			own = o.ID
		}
	}
	dropOrgs(t, h, owner.Org.ID, own)
	if code := m.do(t, http.MethodPost, "/api/v1/auth/switch-org", map[string]any{"organizationId": own}, nil); code != http.StatusOK {
		t.Fatalf("switch to the member's own workspace: %d", code)
	}
	before := h.storedNames(t, "users", mID)[mID]

	var ref refusal
	if code := m.do(t, http.MethodPatch, "/api/v1/me", map[string]any{"name": "Not Mine"}, &ref); code != http.StatusConflict ||
		ref.code() != "scim_managed" || !strings.Contains(ref.Detail, "identity provider") {
		t.Errorf("a SCIM-managed rename: %d %+v, want 409 scim_managed naming the identity provider", code, ref)
	}
	if n := h.storedNames(t, "users", mID)[mID]; n != before {
		t.Errorf("the refused rename changed the name from %q to %q", before, n)
	}
	denied := false
	for _, e := range h.auditEvents(t, ctx, own) {
		if e.Action == "account.update" && e.Outcome == audit.Denied && e.TargetID == mID {
			denied = true
		}
	}
	if !denied {
		t.Error("the refusal is not in the trail as denied")
	}
}

// TestRenameSelfNoWorkspace: a session with no workspace selected is
// asked to select one.
func TestRenameSelfNoWorkspace(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	owner := h.register(t, "E2E rename no org")
	dropOrgs(t, h, owner.Org.ID)
	if err := h.db.Bypass(ctx, "e2e unselect org", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sessions SET organization_id = NULL WHERE user_id = $1`, owner.User.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var ref refusal
	if code := h.do(t, http.MethodPatch, "/api/v1/me", map[string]any{"name": "Nowhere"}, &ref); code != http.StatusConflict ||
		!strings.Contains(ref.Detail, "select a workspace") {
		t.Errorf("no workspace selected: %d %+v, want 409", code, ref)
	}
}

// TestNamesCheckedOnEveryWrite: registration, invite acceptance and SCIM
// hold names to the same rules as a rename, and point at the field.
func TestNamesCheckedOnEveryWrite(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	owner := h.register(t, "E2E names everywhere")
	dropOrgs(t, h, owner.Org.ID)

	for _, c := range []struct {
		field string
		body  map[string]any
	}{
		{"body.name", map[string]any{"name": "\u200b", "orgName": "Fine"}},
		{"body.orgName", map[string]any{"name": "Fine", "orgName": "\u2800"}},
	} {
		c.body["email"] = newID() + "@e2e.test"
		c.body["password"] = "correct horse battery 9"
		var ref refusal
		if code := h.anonymous().do(t, http.MethodPost, "/api/v1/auth/register", c.body, &ref); code != http.StatusUnprocessableEntity ||
			len(ref.Errors) == 0 || ref.Errors[0].Location != c.field {
			t.Errorf("register with a bad %s: %d %+v, want 422 at it", c.field, code, ref)
		}
	}

	inv, code := h.createInvite(t, newID()+"@e2e.test", "role_viewer", 0)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("create invite: %d", code)
	}
	token := inviteToken(t, inv.URL)
	var ref refusal
	if code := h.anonymous().do(t, http.MethodPost, "/api/v1/invites/accept", map[string]any{
		"token": token, "password": "correct horse battery 9", "name": "Line\u2028Break",
	}, &ref); code != http.StatusUnprocessableEntity || len(ref.Errors) == 0 || ref.Errors[0].Location != "body.name" {
		t.Errorf("accept an invite with a bad name: %d %+v, want 422 at body.name", code, ref)
	}
	if code := h.anonymous().do(t, http.MethodPost, "/api/v1/invites/accept", map[string]any{
		"token": token, "password": "correct horse battery 9", "name": "Line Break",
	}, nil); code != http.StatusOK {
		t.Errorf("the invite did not survive the refused attempt: %d", code)
	}

	var key struct {
		Secret string `json:"secret"`
	}
	if code := h.do(t, http.MethodPost, "/api/v1/api-keys", map[string]any{"name": "SCIM", "scopes": []string{"scim:write"}}, &key); code != http.StatusOK {
		t.Fatalf("create a SCIM key: %d", code)
	}
	scim := func(method, path string, body any, out any) int {
		t.Helper()
		b, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, method, h.url+path, strings.NewReader(string(b)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/scim+json")
		req.Header.Set("X-API-Key", key.Secret)
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if out != nil {
			_ = json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}
	user := func(email, formatted string) map[string]any {
		return map[string]any{
			"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"userName": email, "name": map[string]any{"formatted": formatted},
			"emails": []any{map[string]any{"value": email, "primary": true}},
		}
	}
	var scimErr struct {
		ScimType string `json:"scimType"`
	}
	if code := scim(http.MethodPost, "/scim/v2/Users", user(newID()+"@scim.test", "\u202eevil"), &scimErr); code != http.StatusBadRequest ||
		scimErr.ScimType != "invalidValue" {
		t.Errorf("SCIM create with a bad name: %d %+v, want 400 invalidValue", code, scimErr)
	}
	email := newID() + "@scim.test"
	var created struct {
		ID string `json:"id"`
	}
	if code := scim(http.MethodPost, "/scim/v2/Users", user(email, "Provisioned Person"), &created); code != http.StatusCreated {
		t.Fatalf("SCIM create: %d", code)
	}
	scimErr.ScimType = ""
	if code := scim(http.MethodPut, "/scim/v2/Users/"+created.ID, user(email, "\ue000"), &scimErr); code != http.StatusBadRequest ||
		scimErr.ScimType != "invalidValue" {
		t.Errorf("SCIM replace with a bad name: %d %+v, want 400 invalidValue", code, scimErr)
	}
	if n := h.storedNames(t, "users", created.ID)[created.ID]; n != "Provisioned Person" {
		t.Errorf("the refused replace left the name %q", n)
	}
}

// TestRenameOrg renames the current organisation and nothing else, and
// only for a caller holding org:update.
func TestRenameOrg(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	owner := h.register(t, "E2E rename org")
	stranger := (&harness{url: h.url, client: h.client, deps: h.deps, db: h.db}).register(t, "E2E rename org stranger")
	dropOrgs(t, h, owner.Org.ID, stranger.Org.ID)
	editor := h.member(t, owner.Org.ID, "role_editor")

	var got struct{ ID, Slug, Name string }
	if code := h.do(t, http.MethodPatch, "/api/v1/org", map[string]any{"name": " Analytical Engines "}, &got); code != http.StatusOK {
		t.Fatalf("an owner renaming the organisation: %d", code)
	}
	if got.ID != owner.Org.ID || got.Slug != owner.Org.Slug || got.Name != "Analytical Engines" {
		t.Errorf("the answer reads %+v, want the same id and slug %q with the new name", got, owner.Org.Slug)
	}
	s := h.namedSession(t)
	if s.Org == nil || s.Org.Name != "Analytical Engines" || s.Org.Slug != owner.Org.Slug {
		t.Errorf("the session afterwards reads organization %+v", s.Org)
	}
	for _, o := range s.Orgs {
		if o.ID == owner.Org.ID && o.Name != "Analytical Engines" {
			t.Errorf("the organisation list still reads %q", o.Name)
		}
	}
	if es := editor.namedSession(t); es.Org == nil || es.Org.Name != "Analytical Engines" {
		t.Errorf("another member's session reads organization %+v", es.Org)
	}
	if n := h.storedNames(t, "organizations", stranger.Org.ID)[stranger.Org.ID]; n != "E2E rename org stranger" {
		t.Errorf("another organisation was renamed to %q", n)
	}
	renamed(t, h.auditEvents(t, ctx, owner.Org.ID), "org.update", owner.Org.ID, "E2E rename org", "Analytical Engines")

	if code := editor.do(t, http.MethodPatch, "/api/v1/org", map[string]any{"name": "Taken over"}, nil); code != http.StatusForbidden {
		t.Errorf("an editor renaming the organisation: %d, want 403", code)
	}
	if code := h.do(t, http.MethodPatch, "/api/v1/org", map[string]any{"name": "tab\there"}, nil); code != http.StatusUnprocessableEntity {
		t.Errorf("a control character: %d, want 422", code)
	}
	if n := h.storedNames(t, "organizations", owner.Org.ID)[owner.Org.ID]; n != "Analytical Engines" {
		t.Errorf("a refused rename left the name %q", n)
	}
}
