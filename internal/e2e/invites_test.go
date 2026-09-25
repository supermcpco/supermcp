package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/authz"
)

// TestInviteNewAccount invites an address nobody has used, with open
// registration off, and accepts it anonymously: the person gets an account
// in the inviting organisation and nowhere else, and the link works once.
func TestInviteNewAccount(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	h.clearInviteLockouts(t)
	admin := h.register(t, "E2E invites")
	// Registration closes once the owner exists; invites have to work
	// regardless. Set before any request needs it, as TestDCRApproval does.
	h.deps.Identity.Cfg.OpenRegistration = false

	email := "Invitee-" + newID() + "@E2E.test"
	lower := strings.ToLower(email)
	created, code := h.createInvite(t, email, "role_viewer", 0)
	if code != http.StatusCreated {
		t.Fatalf("create invite: %d", code)
	}
	inv := created.Invite
	if inv.Email != lower || inv.RoleName != "viewer" || inv.Status != "pending" || inv.InvitedBy != admin.User.ID ||
		inv.InvitedByName != admin.User.Email {
		t.Errorf("created invite: %+v", inv)
	}
	if d := time.Until(inv.ExpiresAt); d < 6*24*time.Hour || d > 8*24*time.Hour {
		t.Errorf("the default lifetime is %s, expected about seven days", d)
	}
	prefix := h.deps.Config.PublicURL.String() + "/invite/"
	token, ok := strings.CutPrefix(created.URL, prefix)
	if !ok || len(token) != 43 {
		t.Fatalf("the link %q is not %s followed by a 32-byte token", created.URL, prefix)
	}

	// The list never carries the token or the link.
	raw := h.getString(t, "/api/v1/org/invites")
	if strings.Contains(raw, token) {
		t.Fatal("the invite list shows the token")
	}
	invites := h.listInvites(t)
	if len(invites) != 1 || invites[0].ID != inv.ID || invites[0].Status != "pending" {
		t.Fatalf("invites after create: %+v", invites)
	}

	// One open invite per address, whatever case it is typed in.
	var conflict apiError
	if code := h.do(t, http.MethodPost, "/api/v1/org/invites",
		map[string]any{"email": lower, "roleId": "role_editor"}, &conflict); code != http.StatusConflict ||
		!conflict.hasCode("invite_exists") {
		t.Fatalf("second invite for the address: %d %+v", code, conflict)
	}

	anon := h.anonymous()
	if code := anon.do(t, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email": newID() + "@e2e.test", "password": "correct horse battery 9",
	}, nil); code != http.StatusForbidden {
		t.Fatalf("registration should be closed: %d", code)
	}

	// The workspace's own policy is what the new password must meet, and
	// the link holder is told it: they have no session to ask with.
	if code := h.do(t, http.MethodPut, "/api/v1/org/password-policy", map[string]any{
		"minLength": 16, "requireClasses": 2, "history": 5, "maxAgeDays": 0,
	}, nil); code != 200 {
		t.Fatalf("set password policy: %d", code)
	}
	var lookup struct {
		OrgName              string `json:"orgName"`
		Email                string `json:"email"`
		RoleName             string `json:"roleName"`
		RegistrationRequired bool   `json:"registrationRequired"`
		PasswordPolicy       *struct {
			MinLength      int `json:"minLength"`
			RequireClasses int `json:"requireClasses"`
		} `json:"passwordPolicy"`
	}
	if code := anon.do(t, http.MethodPost, "/api/v1/invites/lookup", map[string]any{"token": token}, &lookup); code != 200 ||
		lookup.OrgName != "E2E invites" || lookup.Email != lower || lookup.RoleName != "viewer" || !lookup.RegistrationRequired {
		t.Fatalf("lookup: %d %+v", code, lookup)
	}
	if lookup.PasswordPolicy == nil || lookup.PasswordPolicy.MinLength != 16 || lookup.PasswordPolicy.RequireClasses != 2 {
		t.Fatalf("lookup shows password policy %+v, expected the workspace's", lookup.PasswordPolicy)
	}

	// A new account needs a password that meets that policy.
	if code := anon.do(t, http.MethodPost, "/api/v1/invites/accept", map[string]any{"token": token}, nil); code != http.StatusBadRequest {
		t.Fatalf("accept without a password: %d", code)
	}
	if code := anon.do(t, http.MethodPost, "/api/v1/invites/accept", map[string]any{
		"token": token, "password": "horse battery 9",
	}, nil); code != http.StatusBadRequest {
		t.Fatalf("accept with a password shorter than the workspace allows: %d", code)
	}
	var sess sessionView
	if code := anon.do(t, http.MethodPost, "/api/v1/invites/accept", map[string]any{
		"token": token, "name": "Invitee", "password": "correct horse battery 9",
	}, &sess); code != 200 {
		t.Fatalf("accept: %d", code)
	}
	if anon.cookie == "" {
		t.Fatal("accepting did not start a session")
	}
	if sess.User.Email != lower || sess.Org.ID != admin.Org.ID || len(sess.Orgs) != 1 {
		t.Fatalf("session after accepting: %+v", sess)
	}
	if !slices.Contains(sess.Permissions, authz.OrgRead) || slices.Contains(sess.Permissions, authz.OrgMembersManage) {
		t.Errorf("a viewer holds %v", sess.Permissions)
	}
	newUser := sess.User.ID
	if code := anon.do(t, http.MethodGet, "/api/v1/auth/session", nil, &sess); code != 200 || sess.User.ID != newUser {
		t.Fatalf("the new session does not work: %d %+v", code, sess)
	}

	// Single use.
	again := h.anonymous()
	if code := again.do(t, http.MethodPost, "/api/v1/invites/accept", map[string]any{
		"token": token, "password": "another horse battery 9",
	}, nil); code != http.StatusNotFound {
		t.Fatalf("second accept: %d", code)
	}
	if code := again.do(t, http.MethodPost, "/api/v1/invites/lookup", map[string]any{"token": token}, nil); code != http.StatusNotFound {
		t.Fatalf("lookup after accepting: %d", code)
	}
	if invites := h.listInvites(t); len(invites) != 1 || invites[0].Status != "accepted" || invites[0].AcceptedAt == nil {
		t.Fatalf("invites after accepting: %+v", invites)
	}

	// The member is in the organisation with the invited role, signs in by
	// password, and has no organisation of their own.
	h.assertMember(t, ctx, admin.Org.ID, newUser, "role_viewer")
	var hasPassword bool
	var orgs int
	if err := h.db.Bypass(ctx, "e2e invite check", func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT password_hash IS NOT NULL FROM users WHERE id = $1`, newUser).Scan(&hasPassword); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM organization_members WHERE user_id = $1`, newUser).Scan(&orgs)
	}); err != nil {
		t.Fatal(err)
	}
	if !hasPassword || orgs != 1 {
		t.Errorf("the new account: password %v, %d organisations", hasPassword, orgs)
	}

	// The audit trail records the invite, the account and the join, and
	// never the token or the link.
	events := h.auditEvents(t, ctx, admin.Org.ID)
	all, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(all), token) {
		t.Fatal("the invite token is in the audit trail")
	}
	byAction := map[string]int{}
	for _, e := range events {
		if e.Outcome != "success" || e.Action == "account.register" && e.ActorID == admin.User.ID {
			continue // the owner's own registration is in the trail too
		}
		byAction[e.Action]++
		switch e.Action {
		case "invite.create":
			after, _ := e.Diff["after"].(map[string]any)
			if after["email"] != lower || after["roleId"] != "role_viewer" || after["url"] != nil {
				t.Errorf("invite.create diff: %v", e.Diff)
			}
		case "account.register":
			if e.ActorID != newUser || e.Meta["via"] != "invite" {
				t.Errorf("account.register: actor %s meta %v", e.ActorID, e.Meta)
			}
		case "member.join":
			if e.ActorID != newUser || e.TargetID != newUser || e.Meta["roleId"] != "role_viewer" {
				t.Errorf("member.join: actor %s target %s meta %v", e.ActorID, e.TargetID, e.Meta)
			}
		}
	}
	for _, action := range []string{"invite.create", "account.register", "member.join"} {
		if byAction[action] != 1 {
			t.Errorf("%d successful %s events, expected 1 (have %v)", byAction[action], action, actions(events))
		}
	}
}

// TestInviteExistingAccount accepts invites as people who already have an
// account: the invited address signed in joins, anyone else is refused,
// and an anonymous caller is sent to sign in rather than merged.
func TestInviteExistingAccount(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	h.clearInviteLockouts(t)
	admin := h.register(t, "E2E invites existing")

	joiner := h.anonymous()
	who := joiner.register(t, "Joiner's own")
	stranger := h.anonymous()
	stranger.register(t, "Stranger's own")

	created, code := h.createInvite(t, who.User.Email, "role_editor", 3)
	if code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	if d := time.Until(created.Invite.ExpiresAt); d < 2*24*time.Hour || d > 4*24*time.Hour {
		t.Errorf("a three-day invite lasts %s", d)
	}
	token := inviteToken(t, created.URL)

	var lookup struct {
		RegistrationRequired bool `json:"registrationRequired"`
		PasswordPolicy       any  `json:"passwordPolicy"`
	}
	if code := h.anonymous().do(t, http.MethodPost, "/api/v1/invites/lookup", map[string]any{"token": token}, &lookup); code != 200 ||
		lookup.RegistrationRequired || lookup.PasswordPolicy != nil {
		t.Fatalf("lookup for an existing account: %d %+v", code, lookup)
	}

	// Anonymous, for an address that has an account: sign in first.
	var refused apiError
	if code := h.anonymous().do(t, http.MethodPost, "/api/v1/invites/accept", map[string]any{
		"token": token, "password": "correct horse battery 9",
	}, &refused); code != http.StatusConflict || !refused.hasCode("account_exists") ||
		len(refused.Errors) != 1 || refused.Errors[0].Location != "body.password" {
		t.Fatalf("anonymous accept for an existing account: %d %+v", code, refused)
	}

	// Signed in as somebody else.
	if code := stranger.do(t, http.MethodPost, "/api/v1/invites/accept", map[string]any{"token": token}, nil); code != http.StatusForbidden {
		t.Fatalf("accept as another address: %d", code)
	}
	// Signed in as the address, but offering a password.
	if code := joiner.do(t, http.MethodPost, "/api/v1/invites/accept", map[string]any{
		"token": token, "password": "correct horse battery 9",
	}, nil); code != http.StatusBadRequest {
		t.Fatalf("signed-in accept with a password: %d", code)
	}

	var sess sessionView
	if code := joiner.do(t, http.MethodPost, "/api/v1/invites/accept", map[string]any{"token": token}, &sess); code != 200 {
		t.Fatalf("accept as the invited address: %d", code)
	}
	if sess.Org.ID != admin.Org.ID || sess.User.ID != who.User.ID || len(sess.Orgs) != 2 {
		t.Fatalf("session after joining: %+v", sess)
	}
	if !slices.Contains(sess.Permissions, authz.ConnectorsCreate) {
		t.Errorf("an editor holds %v", sess.Permissions)
	}
	h.assertMember(t, ctx, admin.Org.ID, who.User.ID, "role_editor")

	// Once a member, a second invite is refused.
	var member apiError
	if code := h.do(t, http.MethodPost, "/api/v1/org/invites",
		map[string]any{"email": who.User.Email, "roleId": "role_viewer"}, &member); code != http.StatusConflict ||
		!member.hasCode("already_member") {
		t.Fatalf("invite a member: %d %+v", code, member)
	}

	events := h.auditEvents(t, ctx, admin.Org.ID)
	for _, e := range events {
		if e.Action == "account.register" && e.ActorID == who.User.ID {
			t.Error("joining with an existing account recorded a registration")
		}
	}
	if !slices.Contains(actions(events), "member.join") {
		t.Errorf("no member.join in %v", actions(events))
	}
}

// TestInviteRevokeAndExpiry checks that a revoked or expired link stops
// working, that an expired invite does not block a new one, and that one
// organisation cannot revoke another's invite.
func TestInviteRevokeAndExpiry(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	h.clearInviteLockouts(t)
	h.register(t, "E2E invites revoke")

	revoked, code := h.createInvite(t, newID()+"@e2e.test", "role_viewer", 0)
	if code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	if code := h.do(t, http.MethodDelete, "/api/v1/org/invites/"+revoked.Invite.ID, nil, nil); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	if code := h.do(t, http.MethodDelete, "/api/v1/org/invites/"+revoked.Invite.ID, nil, nil); code != http.StatusNotFound {
		t.Fatalf("revoke twice: %d", code)
	}
	if code := h.anonymous().do(t, http.MethodPost, "/api/v1/invites/accept", map[string]any{
		"token": inviteToken(t, revoked.URL), "password": "correct horse battery 9",
	}, nil); code != http.StatusNotFound {
		t.Fatalf("accept a revoked invite: %d", code)
	}

	expiredEmail := newID() + "@e2e.test"
	expired, code := h.createInvite(t, expiredEmail, "role_viewer", 1)
	if code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	if err := h.db.Bypass(ctx, "e2e expire invite", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE org_invites SET expires_at = now() - interval '1 minute' WHERE id = $1`, expired.Invite.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if code := h.anonymous().do(t, http.MethodPost, "/api/v1/invites/lookup", map[string]any{
		"token": inviteToken(t, expired.URL)}, nil); code != http.StatusNotFound {
		t.Fatalf("lookup an expired invite: %d", code)
	}
	if code := h.anonymous().do(t, http.MethodPost, "/api/v1/invites/accept", map[string]any{
		"token": inviteToken(t, expired.URL), "password": "correct horse battery 9",
	}, nil); code != http.StatusNotFound {
		t.Fatalf("accept an expired invite: %d", code)
	}

	status := map[string]string{}
	for _, inv := range h.listInvites(t) {
		status[inv.ID] = inv.Status
	}
	if status[revoked.Invite.ID] != "revoked" || status[expired.Invite.ID] != "expired" {
		t.Fatalf("statuses: %v", status)
	}

	// The expired invite held the address; a new one takes its place.
	renewed, code := h.createInvite(t, expiredEmail, "role_viewer", 0)
	if code != http.StatusCreated {
		t.Fatalf("invite again after expiry: %d", code)
	}
	status = map[string]string{}
	for _, inv := range h.listInvites(t) {
		status[inv.ID] = inv.Status
	}
	if status[expired.Invite.ID] != "revoked" || status[renewed.Invite.ID] != "pending" {
		t.Fatalf("statuses after renewing: %v", status)
	}

	// Another organisation's administrator sees no such invite.
	outsider := h.anonymous()
	outsider.register(t, "E2E outsider")
	if code := outsider.do(t, http.MethodDelete, "/api/v1/org/invites/"+renewed.Invite.ID, nil, nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant revoke: %d", code)
	}
	if list := outsider.listInvites(t); len(list) != 0 {
		t.Fatalf("an outsider lists %+v", list)
	}
	status = map[string]string{}
	for _, inv := range h.listInvites(t) {
		status[inv.ID] = inv.Status
	}
	if status[renewed.Invite.ID] != "pending" {
		t.Fatalf("the cross-tenant revoke changed the invite: %v", status)
	}
}

// TestInvitePermissions checks who may invite, and to what.
func TestInvitePermissions(t *testing.T) {
	h := start(t)
	h.clearInviteLockouts(t)
	owner := h.register(t, "E2E invites permissions")

	adminMember := h.member(t, owner.Org.ID, "role_admin")
	viewer := h.member(t, owner.Org.ID, "role_viewer")

	if code := viewer.do(t, http.MethodGet, "/api/v1/org/invites", nil, nil); code != http.StatusForbidden {
		t.Fatalf("a viewer lists invites: %d", code)
	}
	if _, code := viewer.createInvite(t, newID()+"@e2e.test", "role_viewer", 0); code != http.StatusForbidden {
		t.Fatalf("a viewer invites: %d", code)
	}

	// An admin may invite, but not to a role that allows everything.
	if _, code := adminMember.createInvite(t, newID()+"@e2e.test", "role_owner", 0); code != http.StatusForbidden {
		t.Fatalf("an admin invites an owner: %d", code)
	}
	if _, code := adminMember.createInvite(t, newID()+"@e2e.test", "role_admin", 0); code != http.StatusCreated {
		t.Fatalf("an admin invites an admin: %d", code)
	}
	if _, code := h.createInvite(t, newID()+"@e2e.test", "role_owner", 0); code != http.StatusCreated {
		t.Fatalf("an owner invites an owner: %d", code)
	}

	if _, code := h.createInvite(t, newID()+"@e2e.test", "role_nonexistent", 0); code != http.StatusNotFound {
		t.Fatalf("invite to an unknown role: %d", code)
	}
	if _, code := h.createInvite(t, newID()+"@e2e.test", "role_viewer", 31); code != http.StatusUnprocessableEntity {
		t.Fatalf("invite for 31 days: %d", code)
	}
}

// TestInviteLookupLockout checks that guessing tokens from one address is
// stopped by the sign-in lockout, even for a token that would work.
func TestInviteLookupLockout(t *testing.T) {
	h := start(t)
	h.clearInviteLockouts(t)
	h.register(t, "E2E invites lockout")
	created, code := h.createInvite(t, newID()+"@e2e.test", "role_viewer", 0)
	if code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	threshold := h.deps.Identity.Cfg.LockoutThreshold
	anon := h.anonymous()
	for i := range threshold {
		guess := strings.Repeat(string(rune('A'+i%26)), 43)
		if code := anon.do(t, http.MethodPost, "/api/v1/invites/lookup", map[string]any{"token": guess}, nil); code != http.StatusNotFound {
			t.Fatalf("guess %d: %d", i, code)
		}
	}
	if code := anon.do(t, http.MethodPost, "/api/v1/invites/lookup", map[string]any{
		"token": inviteToken(t, created.URL)}, nil); code != http.StatusTooManyRequests {
		t.Fatalf("lookup after %d misses: %d", threshold, code)
	}
}

// --- helpers ---------------------------------------------------------------

type inviteView struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	RoleID        string     `json:"roleId"`
	RoleName      string     `json:"roleName"`
	InvitedBy     string     `json:"invitedBy"`
	InvitedByName string     `json:"invitedByName"`
	Status        string     `json:"status"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	AcceptedAt    *time.Time `json:"acceptedAt"`
	RevokedAt     *time.Time `json:"revokedAt"`
}

type createdInvite struct {
	Invite inviteView `json:"invite"`
	URL    string     `json:"url"`
}

type sessionView struct {
	User        struct{ ID, Email string } `json:"user"`
	Org         struct{ ID string }        `json:"organization"`
	Orgs        []struct{ ID string }      `json:"organizations"`
	Permissions []authz.Permission         `json:"permissions"`
}

// anonymous is a harness on the same server with no session.
func (h *harness) anonymous() *harness {
	return &harness{url: h.url, client: h.client, deps: h.deps, connectors: h.connectors, servers: h.servers, db: h.db}
}

func (h *harness) createInvite(t *testing.T, email, roleID string, days int) (createdInvite, int) {
	t.Helper()
	body := map[string]any{"email": email, "roleId": roleID}
	if days > 0 {
		body["expiresInDays"] = days
	}
	var out createdInvite
	code := h.do(t, http.MethodPost, "/api/v1/org/invites", body, &out)
	return out, code
}

func (h *harness) listInvites(t *testing.T) []inviteView {
	t.Helper()
	var out struct {
		Invites []inviteView `json:"invites"`
	}
	if code := h.do(t, http.MethodGet, "/api/v1/org/invites", nil, &out); code != 200 {
		t.Fatalf("list invites: %d", code)
	}
	return out.Invites
}

func inviteToken(t *testing.T, link string) string {
	t.Helper()
	_, token, ok := strings.Cut(link, "/invite/")
	if !ok || token == "" {
		t.Fatalf("no token in %q", link)
	}
	return token
}

// assertMember checks the membership and the role binding the invite
// made. It reads the tables rather than members-list, which is another
// work package's endpoint.
func (h *harness) assertMember(t *testing.T, ctx context.Context, orgID, userID, roleID string) {
	t.Helper()
	var active bool
	var sources []string
	if err := h.db.Bypass(ctx, "e2e invite membership", func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT deactivated_at IS NULL FROM organization_members
			WHERE organization_id = $1 AND user_id = $2`, orgID, userID).Scan(&active); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT source FROM role_bindings WHERE organization_id = $1
			AND principal_kind = 'user' AND principal_id = $2 AND role_id = $3 AND scope_kind = 'org'`, orgID, userID, roleID)
		if err != nil {
			return err
		}
		sources, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	}); err != nil {
		t.Fatalf("membership of %s: %v", userID, err)
	}
	if !active || !slices.Equal(sources, []string{"invite"}) {
		t.Fatalf("membership of %s: active %v, %s bindings from %v", userID, active, roleID, sources)
	}
}

// clearInviteLockouts forgets failed invite lookups from earlier tests and
// runs, which all come from the loopback address.
func (h *harness) clearInviteLockouts(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	clear := func() error {
		return h.db.Bypass(ctx, "e2e invite lockouts", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM login_lockouts WHERE key LIKE 'invite:%'`)
			return err
		})
	}
	if err := clear(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clear() })
}
