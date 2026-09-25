package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// ownerBinding returns the binding through which m holds the owner role
// organisation-wide.
func ownerBinding(t *testing.T, m memberBody) string {
	t.Helper()
	for _, r := range m.Roles {
		if r.RoleID == "role_owner" && r.ScopeKind == "org" {
			return r.BindingID
		}
	}
	t.Fatalf("%s holds no owner binding: %+v", m.UserID, m.Roles)
	return ""
}

// deleteOwnerBinding takes the owner role away through the roles API. It
// reports rather than fails, so it can run off the test goroutine; h is
// only read, so two harnesses may call it at once.
func (h *harness) deleteOwnerBinding(ctx context.Context, bindingID string) (int, apiError, error) {
	var e apiError
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, h.url+"/api/v1/roles/role_owner/bindings/"+bindingID, http.NoBody)
	if err != nil {
		return 0, e, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Cookie", h.cookie)
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, e, fmt.Errorf("delete binding: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
			return resp.StatusCode, e, fmt.Errorf("decode error reply: %w", err)
		}
	}
	return resp.StatusCode, e, nil
}

// TestRolesLastOwnerCountsActiveOwnersOnly takes the owner role away
// through the roles API when the only other owner is deactivated. The
// deactivated owner's binding still exists but cannot sign in or grant
// anything, so it must not count.
func TestRolesLastOwnerCountsActiveOwnersOnly(t *testing.T) {
	h := start(t)
	ctx := t.Context()
	owner := h.register(t, "E2E roles last owner")
	dropOrgs(t, h, owner.Org.ID)
	admin := h.member(t, owner.Org.ID, "role_admin")
	second := h.member(t, owner.Org.ID, "role_owner")
	secondID, _ := second.whoAmI(t)
	if code := h.patchMember(t, secondID, map[string]any{"status": "deactivated"}, nil); code != http.StatusOK {
		t.Fatalf("deactivate the second owner: %d", code)
	}
	list := h.members(t)
	if list[secondID].Status != "deactivated" {
		t.Fatalf("the second owner reads %+v", list[secondID])
	}
	activeBinding := ownerBinding(t, list[owner.User.ID])
	deactivatedBinding := ownerBinding(t, list[secondID])

	code, e, err := admin.deleteOwnerBinding(ctx, activeBinding)
	if err != nil {
		t.Fatal(err)
	}
	if code != http.StatusConflict || !e.hasCode("last_owner") {
		t.Errorf("take the owner role from the last active owner: %d %v, want 409 last_owner", code, e.codes())
	}
	if !h.members(t)[owner.User.ID].holds("role_owner") {
		t.Error("the refused change took the owner role away")
	}

	// The deactivated owner's binding is not what keeps the organisation
	// governable, so it may go.
	code, e, err = admin.deleteOwnerBinding(ctx, deactivatedBinding)
	if err != nil {
		t.Fatal(err)
	}
	if code != http.StatusNoContent {
		t.Errorf("take the owner role from a deactivated owner: %d %v, want 204", code, e.codes())
	}
}

// TestRolesConcurrentOwnerRemoval has two administrators each take the
// owner role from one of the last two owners at the same moment. Exactly
// one may succeed: the organisation's row lock makes the second see the
// first's change.
//
// Left to the scheduler the two requests rarely overlap, so a blocker
// holds a lock on role_bindings that stops both DELETEs until both
// requests are inside their transactions. Without the organisation lock
// each would then count the other's owner, still uncommitted, and both
// would succeed.
func TestRolesConcurrentOwnerRemoval(t *testing.T) {
	h := start(t)
	ctx := t.Context()
	owner := h.register(t, "E2E roles concurrent owners")
	dropOrgs(t, h, owner.Org.ID)
	second := h.member(t, owner.Org.ID, "role_owner")
	secondID, _ := second.whoAmI(t)
	admins := []*harness{h.member(t, owner.Org.ID, "role_admin"), h.member(t, owner.Org.ID, "role_admin")}
	list := h.members(t)
	bindings := []string{ownerBinding(t, list[owner.User.ID]), ownerBinding(t, list[secondID])}

	type result struct {
		code int
		e    apiError
		err  error
	}
	blocker, err := h.db.Maint.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blocker.Rollback(context.Background()) })
	if _, err := blocker.Exec(ctx, `LOCK TABLE role_bindings IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	results := make(chan result, len(admins))
	for i, a := range admins {
		go func() {
			code, e, err := a.deleteOwnerBinding(ctx, bindings[i])
			results <- result{code, e, err}
		}()
	}
	waitForBlocked(t, h, len(admins))
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var ok, refused int
	for range admins {
		r := <-results
		switch {
		case r.err != nil:
			t.Error(r.err)
		case r.code == http.StatusNoContent:
			ok++
		case r.code == http.StatusConflict && r.e.hasCode("last_owner"):
			refused++
		default:
			t.Errorf("unexpected reply: %d %v", r.code, r.e.codes())
		}
	}
	if ok != 1 || refused != 1 {
		t.Errorf("%d removals succeeded and %d were refused, want exactly one of each", ok, refused)
	}

	var owners int
	if err := h.db.Bypass(ctx, "e2e count owners", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM role_bindings b
			JOIN organization_members m ON m.organization_id = b.organization_id AND m.user_id = b.principal_id
			WHERE b.organization_id = $1 AND b.role_id = 'role_owner' AND b.principal_kind = 'user'
			  AND b.scope_kind = 'org' AND m.deactivated_at IS NULL`, owner.Org.ID).Scan(&owners)
	}); err != nil {
		t.Fatal(err)
	}
	if owners != 1 {
		t.Errorf("%d active owners left, want 1", owners)
	}
}

// waitForBlocked waits until n sessions in this database are waiting on a
// lock another session holds.
func waitForBlocked(t *testing.T, h *harness, n int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var blocked int
		if err := h.db.Maint.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND cardinality(pg_blocking_pids(pid)) > 0`).Scan(&blocked); err != nil {
			t.Fatalf("waiting for %d blocked sessions: %v", n, err)
		}
		if blocked >= n {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%d sessions blocked, want %d: %v", blocked, n, ctx.Err())
		case <-tick.C:
		}
	}
}
