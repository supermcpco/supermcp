package e2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
)

type memberRole struct {
	RoleID    string `json:"roleId"`
	RoleName  string `json:"roleName"`
	BindingID string `json:"bindingId"`
	Source    string `json:"source"`
	ScopeKind string `json:"scopeKind"`
}

type memberBody struct {
	UserID       string       `json:"userId"`
	Email        string       `json:"email"`
	Status       string       `json:"status"`
	Source       string       `json:"source"`
	Roles        []memberRole `json:"roles"`
	LastSignInAt *time.Time   `json:"lastSignInAt"`
	JoinedAt     time.Time    `json:"joinedAt"`
	IsSelf       bool         `json:"isSelf"`
	ScimManaged  bool         `json:"scimManaged"`
}

func (m memberBody) holds(roleID string) bool {
	for _, r := range m.Roles {
		if r.RoleID == roleID {
			return true
		}
	}
	return false
}

const membersPath = "/api/v1/org/members"

// members reads the member list as h and fails the test on anything but 200.
func (h *harness) members(t *testing.T) map[string]memberBody {
	t.Helper()
	var out struct {
		Members []memberBody `json:"members"`
	}
	if code := h.do(t, http.MethodGet, membersPath, nil, &out); code != http.StatusOK {
		t.Fatalf("list members: %d", code)
	}
	byID := make(map[string]memberBody, len(out.Members))
	for _, m := range out.Members {
		byID[m.UserID] = m
	}
	return byID
}

// whoAmI returns the signed-in user, or "" when the session is anonymous.
func (h *harness) whoAmI(t *testing.T) (id, email string) {
	t.Helper()
	var s struct {
		User *struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
		Anonymous bool `json:"anonymous"`
	}
	if code := h.do(t, http.MethodGet, "/api/v1/auth/session", nil, &s); code != http.StatusOK {
		t.Fatalf("read session: %d", code)
	}
	if s.Anonymous || s.User == nil {
		return "", ""
	}
	return s.User.ID, s.User.Email
}

// patchMember sends a member update and decodes an error reply into e.
func (h *harness) patchMember(t *testing.T, userID string, body map[string]any, e *apiError) int {
	t.Helper()
	if e == nil {
		return h.do(t, http.MethodPatch, membersPath+"/"+userID, body, nil)
	}
	return h.do(t, http.MethodPatch, membersPath+"/"+userID, body, e)
}

func dropOrgs(t *testing.T, h *harness, ids ...string) {
	t.Helper()
	ctx := context.Background()
	t.Cleanup(func() {
		_ = h.db.Bypass(ctx, "e2e cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = ANY($1)`, ids)
			return err
		})
	})
}

// TestMembersList lists an owner and a viewer with their roles and
// sources, and checks that reading the list is all a viewer may do.
func TestMembersList(t *testing.T) {
	h := start(t)
	owner := h.register(t, "E2E members list")
	dropOrgs(t, h, owner.Org.ID)
	viewer := h.member(t, owner.Org.ID, "role_viewer")
	viewerID, viewerEmail := viewer.whoAmI(t)

	list := h.members(t)
	if len(list) != 2 {
		t.Fatalf("the list holds %d members, expected the owner and the viewer: %+v", len(list), list)
	}
	o := list[owner.User.ID]
	if !o.IsSelf || o.Status != "active" || o.Source != "password" || !o.holds("role_owner") || o.ScimManaged {
		t.Errorf("the owner reads %+v", o)
	}
	if o.LastSignInAt == nil || o.JoinedAt.IsZero() {
		t.Errorf("the owner has no last sign-in or join time: %+v", o)
	}
	v := list[viewerID]
	if v.IsSelf || v.Email != viewerEmail || v.Source != "password" || !v.holds("role_viewer") {
		t.Errorf("the viewer reads %+v", v)
	}
	if len(v.Roles) != 1 || v.Roles[0].RoleName != "viewer" || v.Roles[0].ScopeKind != "org" || v.Roles[0].BindingID == "" {
		t.Errorf("the viewer's roles read %+v", v.Roles)
	}

	// A viewer reads the list, sees themselves, and can change nothing.
	seen := viewer.members(t)
	if !seen[viewerID].IsSelf || seen[owner.User.ID].IsSelf {
		t.Errorf("isSelf is wrong from the viewer's side: %+v", seen)
	}
	if code := viewer.patchMember(t, owner.User.ID, map[string]any{"status": "deactivated"}, nil); code != http.StatusForbidden {
		t.Errorf("a viewer deactivating the owner: %d, want 403", code)
	}
	if code := viewer.patchMember(t, owner.User.ID, map[string]any{"roleId": "role_viewer"}, nil); code != http.StatusForbidden {
		t.Errorf("a viewer changing the owner's role: %d, want 403", code)
	}
	if code := viewer.do(t, http.MethodDelete, membersPath+"/"+owner.User.ID, nil, nil); code != http.StatusForbidden {
		t.Errorf("a viewer removing the owner: %d, want 403", code)
	}
}

// TestMembersRefusals covers every change the API refuses and why.
func TestMembersRefusals(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	owner := h.register(t, "E2E members refusals")
	admin := h.member(t, owner.Org.ID, "role_admin")
	viewer := h.member(t, owner.Org.ID, "role_viewer")
	viewerID, _ := viewer.whoAmI(t)
	other := &harness{url: h.url, client: h.client, deps: h.deps, db: h.db}
	stranger := other.register(t, "E2E members stranger")
	dropOrgs(t, h, owner.Org.ID, stranger.Org.ID)

	t.Run("self", func(t *testing.T) {
		cases := []struct {
			name   string
			method string
			body   map[string]any
		}{
			{"deactivate", http.MethodPatch, map[string]any{"status": "deactivated"}},
			{"demote", http.MethodPatch, map[string]any{"roleId": "role_viewer"}},
			{"remove", http.MethodDelete, nil},
		}
		for _, c := range cases {
			var e apiError
			if code := h.do(t, c.method, membersPath+"/"+owner.User.ID, c.body, &e); code != http.StatusConflict || !e.hasCode("self") {
				t.Errorf("%s yourself: %d %v, want 409 self", c.name, code, e.codes())
			}
		}
	})

	t.Run("last owner", func(t *testing.T) {
		cases := []struct {
			name   string
			method string
			body   map[string]any
		}{
			{"deactivate", http.MethodPatch, map[string]any{"status": "deactivated"}},
			{"remove", http.MethodDelete, nil},
			{"demote", http.MethodPatch, map[string]any{"roleId": "role_admin"}},
		}
		for _, c := range cases {
			var e apiError
			if code := admin.do(t, c.method, membersPath+"/"+owner.User.ID, c.body, &e); code != http.StatusConflict || !e.hasCode("last_owner") {
				t.Errorf("%s the last owner: %d %v, want 409 last_owner", c.name, code, e.codes())
			}
		}
		o := h.members(t)[owner.User.ID]
		if o.Status != "active" || !o.holds("role_owner") {
			t.Errorf("a refused change touched the owner: %+v", o)
		}
	})

	t.Run("owner grant needs an owner", func(t *testing.T) {
		if code := admin.patchMember(t, viewerID, map[string]any{"roleId": "role_owner"}, nil); code != http.StatusForbidden {
			t.Errorf("an admin making someone an owner: %d, want 403", code)
		}
	})

	t.Run("role change", func(t *testing.T) {
		var got memberBody
		if code := admin.do(t, http.MethodPatch, membersPath+"/"+viewerID, map[string]any{"roleId": "role_editor"}, &got); code != http.StatusOK {
			t.Fatalf("change the viewer to editor: %d", code)
		}
		if len(got.Roles) != 1 || got.Roles[0].RoleID != "role_editor" || got.Roles[0].Source != "manual" {
			t.Errorf("after the change the member holds %+v", got.Roles)
		}
		var e apiError
		if code := admin.patchMember(t, viewerID, map[string]any{"roleId": "role_nope"}, &e); code != http.StatusNotFound {
			t.Errorf("an unknown role: %d, want 404", code)
		}
		if code := admin.patchMember(t, viewerID, map[string]any{}, nil); code != http.StatusBadRequest {
			t.Errorf("an empty change: %d, want 400", code)
		}
		if code := admin.patchMember(t, viewerID, map[string]any{"roleId": "role_viewer", "status": "active"}, nil); code != http.StatusBadRequest {
			t.Errorf("two changes at once: %d, want 400", code)
		}
	})

	t.Run("cross tenant", func(t *testing.T) {
		if code := h.patchMember(t, stranger.User.ID, map[string]any{"status": "deactivated"}, nil); code != http.StatusNotFound {
			t.Errorf("deactivate another tenant's user: %d, want 404", code)
		}
		if code := h.patchMember(t, stranger.User.ID, map[string]any{"roleId": "role_viewer"}, nil); code != http.StatusNotFound {
			t.Errorf("change another tenant's user's role: %d, want 404", code)
		}
		if code := h.do(t, http.MethodDelete, membersPath+"/"+stranger.User.ID, nil, nil); code != http.StatusNotFound {
			t.Errorf("remove another tenant's user: %d, want 404", code)
		}
		if _, email := other.whoAmI(t); email != stranger.User.Email {
			t.Errorf("the stranger's session was touched: %q", email)
		}
	})

	t.Run("scim managed", func(t *testing.T) {
		if err := h.db.Bypass(ctx, "e2e scim member", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO scim_users (organization_id, user_id, user_name) VALUES ($1, $2, $3)`,
				owner.Org.ID, viewerID, "viewer@idp.test")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		for _, status := range []string{"deactivated", "active"} {
			var e apiError
			if code := h.patchMember(t, viewerID, map[string]any{"status": status}, &e); code != http.StatusConflict || !e.hasCode("scim_managed") {
				t.Errorf("set a SCIM member %s: %d %v, want 409 scim_managed", status, code, e.codes())
			}
		}
		var e apiError
		if code := h.do(t, http.MethodDelete, membersPath+"/"+viewerID, nil, &e); code != http.StatusConflict || !e.hasCode("scim_managed") {
			t.Errorf("remove a SCIM member: %d %v, want 409 scim_managed", code, e.codes())
		}
		if code := h.patchMember(t, viewerID, map[string]any{"roleId": "role_viewer"}, nil); code != http.StatusOK {
			t.Errorf("change a SCIM member's role: %d, want 200", code)
		}
		v := h.members(t)[viewerID]
		if !v.ScimManaged || v.Source != "scim" || v.Status != "active" {
			t.Errorf("the SCIM member reads %+v", v)
		}
	})
}

// TestMemberDeactivateRevokes deactivates a member and checks that their
// session and API key stop working at once and that they cannot switch
// back in, then reactivates them and checks that they can.
func TestMemberDeactivateRevokes(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	owner := h.register(t, "E2E members deactivate")
	dropOrgs(t, h, owner.Org.ID)
	m := h.member(t, owner.Org.ID, "role_viewer")
	memberID, memberEmail := m.whoAmI(t)

	var key struct {
		Secret string `json:"secret"`
	}
	if code := m.do(t, http.MethodPost, "/api/v1/api-keys", map[string]any{"name": "member"}, &key); code != http.StatusOK || key.Secret == "" {
		t.Fatalf("the member creates a key: %d", code)
	}
	// The key is limited to tools, so the member list refuses it with a
	// 403: it is authenticated. After deactivation it is not, and that is a
	// 401.
	if code := m.withKey(t, key.Secret); code != http.StatusForbidden {
		t.Fatalf("the member's tools key on the member list before deactivation: %d, want 403", code)
	}

	var got memberBody
	if code := h.do(t, http.MethodPatch, membersPath+"/"+memberID, map[string]any{"status": "deactivated"}, &got); code != http.StatusOK {
		t.Fatalf("deactivate: %d", code)
	}
	if got.Status != "deactivated" {
		t.Errorf("after deactivation the member reads %+v", got)
	}
	if id, _ := m.whoAmI(t); id != "" {
		t.Error("the deactivated member's session still works")
	}
	if code := m.do(t, http.MethodGet, membersPath, nil, nil); code != http.StatusUnauthorized {
		t.Errorf("the deactivated member's session lists members: %d, want 401", code)
	}
	if code := m.withKey(t, key.Secret); code != http.StatusUnauthorized {
		t.Errorf("the deactivated member's key lists members: %d, want 401", code)
	}
	// They can still sign in, to their own workspace, but not come back here.
	m.signIn(t, memberEmail)
	if code := m.do(t, http.MethodPost, "/api/v1/auth/switch-org", map[string]any{"organizationId": owner.Org.ID}, nil); code == http.StatusOK {
		t.Error("a deactivated member switched into the organisation")
	}

	got = memberBody{}
	if code := h.do(t, http.MethodPatch, membersPath+"/"+memberID, map[string]any{"status": "active"}, &got); code != http.StatusOK || got.Status != "active" {
		t.Fatalf("reactivate: %d %+v", code, got)
	}
	if code := m.do(t, http.MethodPost, "/api/v1/auth/switch-org", map[string]any{"organizationId": owner.Org.ID}, nil); code != http.StatusOK {
		t.Fatalf("the reactivated member switches in: %d", code)
	}
	if !m.members(t)[memberID].holds("role_viewer") {
		t.Error("the reactivated member lost their role")
	}

	events := h.auditEvents(t, ctx, owner.Org.ID)
	want := map[string]bool{"member.deactivate": false, "member.reactivate": false}
	for _, e := range events {
		if _, ok := want[e.Action]; ok && e.Outcome == audit.Success && e.TargetID == memberID && e.TargetDisplay == memberEmail {
			want[e.Action] = true
		}
	}
	for action, ok := range want {
		if !ok {
			t.Errorf("no %s event naming the member; the trail holds %v", action, actions(events))
		}
	}
}

// TestMemberRemove removes a member: their bindings and membership go,
// their account stays, and the audit trail names them.
func TestMemberRemove(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	owner := h.register(t, "E2E members remove")
	dropOrgs(t, h, owner.Org.ID)
	m := h.member(t, owner.Org.ID, "role_editor")
	memberID, memberEmail := m.whoAmI(t)

	if code := h.do(t, http.MethodDelete, membersPath+"/"+memberID, nil, nil); code != http.StatusNoContent {
		t.Fatalf("remove: %d", code)
	}
	if _, ok := h.members(t)[memberID]; ok {
		t.Error("the removed member is still listed")
	}
	if id, _ := m.whoAmI(t); id != "" {
		t.Error("the removed member's session still works")
	}
	var bindings, memberships, users int
	if err := h.db.Bypass(ctx, "e2e check removal", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM role_bindings WHERE organization_id = $1 AND principal_kind = 'user' AND principal_id = $2),
			(SELECT count(*) FROM organization_members WHERE organization_id = $1 AND user_id = $2),
			(SELECT count(*) FROM users WHERE id = $2)`, owner.Org.ID, memberID).Scan(&bindings, &memberships, &users)
	}); err != nil {
		t.Fatal(err)
	}
	if bindings != 0 || memberships != 0 || users != 1 {
		t.Errorf("after removal: %d bindings, %d memberships, %d user rows; want 0, 0, 1", bindings, memberships, users)
	}
	if code := h.do(t, http.MethodDelete, membersPath+"/"+memberID, nil, nil); code != http.StatusNotFound {
		t.Errorf("remove twice: %d, want 404", code)
	}

	var removed *audit.Record
	events := h.auditEvents(t, ctx, owner.Org.ID)
	for i, e := range events {
		if e.Action == "member.remove" && e.Outcome == audit.Success {
			removed = &events[i]
		}
	}
	if removed == nil {
		t.Fatalf("no member.remove event; the trail holds %v", actions(events))
	}
	before, _ := removed.Diff["before"].(map[string]any)
	if removed.TargetID != memberID || removed.TargetDisplay != memberEmail || before["email"] != memberEmail {
		t.Errorf("member.remove names %q %q with diff %v", removed.TargetID, removed.TargetDisplay, removed.Diff)
	}
	if removed.ActorID != owner.User.ID {
		t.Errorf("member.remove names actor %q, expected %q", removed.ActorID, owner.User.ID)
	}
}

// TestDeactivatedMemberFailsClosed deactivates a member behind the API's
// back, so their session is not revoked, and checks that the evaluator no
// longer grants them anything once its cache is dropped.
func TestDeactivatedMemberFailsClosed(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	owner := h.register(t, "E2E members fail closed")
	dropOrgs(t, h, owner.Org.ID)
	m := h.member(t, owner.Org.ID, "role_viewer")
	memberID, _ := m.whoAmI(t)
	m.members(t)

	if err := h.db.Bypass(ctx, "e2e deactivate without revoking", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE organization_members SET deactivated_at = now() WHERE organization_id = $1 AND user_id = $2`,
			owner.Org.ID, memberID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h.deps.Authz.Invalidate(owner.Org.ID, "user", memberID)
	if id, _ := m.whoAmI(t); id != memberID {
		t.Fatal("the test needs the member's session to outlive the deactivation")
	}
	if code := m.do(t, http.MethodGet, membersPath, nil, nil); code != http.StatusForbidden {
		t.Errorf("a deactivated member with a live session lists members: %d, want 403", code)
	}
}

// withKey lists members with an API key instead of the session.
func (h *harness) withKey(t *testing.T, key string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url+membersPath, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", key)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// signIn signs in with the password every e2e account is registered with.
func (h *harness) signIn(t *testing.T, email string) {
	t.Helper()
	if code := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email": email, "password": "correct horse battery 9",
	}, nil); code != http.StatusOK {
		t.Fatalf("sign in as %s: %d", email, code)
	}
}
