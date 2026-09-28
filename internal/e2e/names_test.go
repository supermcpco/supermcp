package e2e

import (
	"context"
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
