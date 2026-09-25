package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
)

type retentionBody struct {
	Days        int    `json:"days"`
	Configured  bool   `json:"configured"`
	DefaultDays int    `json:"defaultDays"`
	MinDays     int    `json:"minDays"`
	MaxDays     int    `json:"maxDays"`
	Detail      string `json:"detail"`
}

// TestAuditRetentionThroughTheAPI sets a workspace's retention window over
// HTTP, reads it back, and checks what is refused and what is recorded.
func TestAuditRetentionThroughTheAPI(t *testing.T) {
	h := start(t)
	ctx := context.Background()
	admin := h.register(t, "E2E retention")
	const path = "/api/v1/audit/retention"

	var got retentionBody
	if code := h.do(t, http.MethodGet, path, nil, &got); code != 200 {
		t.Fatalf("read retention: %d", code)
	}
	if got.Days != audit.DefaultRetentionDays || got.Configured {
		t.Errorf("a new workspace reports %+v; it should be on the %d-day default", got, audit.DefaultRetentionDays)
	}
	if got.MinDays != audit.MinRetentionDays || got.MaxDays != audit.MaxRetentionDays || got.DefaultDays != audit.DefaultRetentionDays {
		t.Errorf("the bounds read %d..%d (default %d); expected %d..%d (default %d)", got.MinDays, got.MaxDays, got.DefaultDays,
			audit.MinRetentionDays, audit.MaxRetentionDays, audit.DefaultRetentionDays)
	}

	got = retentionBody{}
	if code := h.do(t, http.MethodPut, path, map[string]any{"days": 180}, &got); code != 200 {
		t.Fatalf("set retention to 180 days: %d %+v", code, got)
	}
	if got.Days != 180 || !got.Configured {
		t.Errorf("setting 180 days answered %+v", got)
	}
	got = retentionBody{}
	if code := h.do(t, http.MethodGet, path, nil, &got); code != 200 || got.Days != 180 || !got.Configured {
		t.Fatalf("reading back after setting 180 days: %d %+v", code, got)
	}

	outOfRange := []struct {
		name string
		days int
		says string
	}{
		{name: "below the floor", days: audit.MinRetentionDays - 1, says: "at least 90 days"},
		{name: "above the ceiling", days: audit.MaxRetentionDays + 1, says: "at most 36500 days"},
	}
	for _, tt := range outOfRange {
		t.Run(tt.name, func(t *testing.T) {
			var refusal retentionBody
			if code := h.do(t, http.MethodPut, path, map[string]any{"days": tt.days}, &refusal); code != 422 {
				t.Fatalf("setting %d days answered %d; it should be refused with 422", tt.days, code)
			}
			if !strings.Contains(refusal.Detail, tt.says) {
				t.Errorf("refusing %d days said %q; it should explain the bound (%q)", tt.days, refusal.Detail, tt.says)
			}
		})
	}
	got = retentionBody{}
	if code := h.do(t, http.MethodGet, path, nil, &got); code != 200 || got.Days != 180 {
		t.Fatalf("a refused change moved the window: %d %+v", code, got)
	}

	// Reading needs audit:read and changing needs audit:policy:manage; the
	// auditor role has the first and not the second.
	roles := []struct {
		role    string
		readOK  bool
		writeOK bool
	}{
		{role: "role_viewer"},
		{role: "role_auditor", readOK: true},
	}
	for _, tt := range roles {
		t.Run(tt.role, func(t *testing.T) {
			m := h.member(t, admin.Org.ID, tt.role)
			want := map[bool]int{true: 200, false: 403}
			if code := m.do(t, http.MethodGet, path, nil, nil); code != want[tt.readOK] {
				t.Errorf("%s reading retention answered %d, expected %d", tt.role, code, want[tt.readOK])
			}
			if code := m.do(t, http.MethodPut, path, map[string]any{"days": 120}, nil); code != want[tt.writeOK] {
				t.Errorf("%s setting retention answered %d, expected %d", tt.role, code, want[tt.writeOK])
			}
		})
	}
	got = retentionBody{}
	if code := h.do(t, http.MethodGet, path, nil, &got); code != 200 || got.Days != 180 {
		t.Fatalf("a refused member moved the window: %d %+v", code, got)
	}

	var set *audit.Record
	var failures int
	events := h.auditEvents(t, ctx, admin.Org.ID)
	for i, e := range events {
		if e.Action != "audit.retention.set" {
			continue
		}
		switch e.Outcome {
		case audit.Success:
			set = &events[i]
		case audit.Failure:
			failures++
		}
	}
	if set == nil {
		t.Fatal("the retention change is not in the audit trail")
	}
	if set.ActorID != admin.User.ID {
		t.Errorf("the retention change names actor %q, expected %q", set.ActorID, admin.User.ID)
	}
	before, _ := set.Diff["before"].(map[string]any)
	after, _ := set.Diff["after"].(map[string]any)
	if before["retentionDays"] != float64(audit.DefaultRetentionDays) || after["retentionDays"] != float64(180) {
		t.Errorf("the retention change recorded %v; it should say %d days became 180", set.Diff, audit.DefaultRetentionDays)
	}
	if failures != len(outOfRange) {
		t.Errorf("%d refused retention changes are in the trail, expected %d", failures, len(outOfRange))
	}
}

// member signs up another person, makes them a member of orgID holding
// roleID, and returns a harness signed in as them there.
func (h *harness) member(t *testing.T, orgID, roleID string) *harness {
	t.Helper()
	m := &harness{url: h.url, client: h.client, deps: h.deps, connectors: h.connectors, servers: h.servers, db: h.db}
	who := m.register(t, "E2E member")
	ctx := context.Background()
	if err := h.db.Bypass(ctx, "e2e add member", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organization_members (user_id, organization_id) VALUES ($1, $2)`,
			who.User.ID, orgID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id)
			VALUES ($1, $2, 'user', $3, $4)`, newID(), orgID, who.User.ID, roleID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if code := m.do(t, http.MethodPost, "/api/v1/auth/switch-org", map[string]any{"organizationId": orgID}, nil); code != 200 {
		t.Fatalf("switch to organisation %s: %d", orgID, code)
	}
	return m
}
