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
)

// A workspace's own detectors, over HTTP and through a real tool call:
// the pattern is tried and validated before it is stored, a policy picks
// it by name, a call carrying a match is refused or masked on another
// replica's reader, and a delete a policy depends on is refused unless
// forced.

type customDetectorBody struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Detector string `json:"detector"`
	Version  int64  `json:"version"`
	Enabled  bool   `json:"enabled"`
}

// contractID is an invented identifier of the shape the detector below
// is written for.
const contractID = "CN-123456"

func TestDLPCustomDetectors(t *testing.T) {
	s := newPolicySetup(t, "E2E DLP detectors")
	h := s.h
	h.listen(t)

	// --- trying a pattern -------------------------------------------------
	var raw json.RawMessage
	if code := h.do(t, http.MethodPost, "/api/v1/dlp/detectors/test", map[string]any{
		"pattern": `\bCN-\d{6}\b`, "samples": []string{"id " + contractID, "nothing here"},
	}, &raw); code != http.StatusOK {
		t.Fatalf("test a pattern: %d %s", code, raw)
	}
	if strings.Contains(string(raw), contractID) {
		t.Errorf("the test route quoted a sample back: %s", raw)
	}
	var tried struct {
		Samples []struct {
			Index   int  `json:"index"`
			Matched bool `json:"matched"`
			Matches []struct {
				Start int `json:"start"`
				End   int `json:"end"`
			} `json:"matches"`
		} `json:"samples"`
	}
	if err := json.Unmarshal(raw, &tried); err != nil {
		t.Fatal(err)
	}
	if len(tried.Samples) != 2 || !tried.Samples[0].Matched || tried.Samples[1].Matched ||
		len(tried.Samples[0].Matches) != 1 || tried.Samples[0].Matches[0].Start != 3 || tried.Samples[0].Matches[0].End != 12 {
		t.Errorf("tried %+v", tried)
	}
	var bad apiError
	if code := h.do(t, http.MethodPost, "/api/v1/dlp/detectors/test", map[string]any{
		"pattern": `CN-\d*|`, "samples": []string{"x"},
	}, &bad); code != http.StatusUnprocessableEntity || len(bad.Errors) == 0 || bad.Errors[0].Location != "body.pattern" {
		t.Errorf("a pattern matching the empty string: %d %+v", code, bad)
	}

	// --- saving it --------------------------------------------------------
	detector := map[string]any{"name": "contract_id", "description": "Contract ids", "pattern": `\bCN-\d{6}\b`,
		"mustMatch": []string{contractID, "CN-12"}, "mustNotMatch": []string{"CN-1234567"}}
	bad = apiError{}
	if code := h.do(t, http.MethodPost, "/api/v1/dlp/detectors", detector, &bad); code != http.StatusUnprocessableEntity ||
		len(bad.Errors) == 0 || bad.Errors[0].Location != "body.mustMatch[1]" {
		t.Fatalf("a failing sample: %d %+v", code, bad)
	}
	if strings.Contains(bad.Detail, "CN-12") {
		t.Errorf("the refusal quotes the sample: %q", bad.Detail)
	}
	detector["mustMatch"] = []string{contractID}
	var created customDetectorBody
	if code := h.do(t, http.MethodPost, "/api/v1/dlp/detectors", detector, &created); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	if created.Detector != "custom:contract_id" || created.Version != 1 || !created.Enabled {
		t.Errorf("created %+v", created)
	}
	var listed struct {
		Detectors []struct{ Name string } `json:"detectors"`
		Custom    []customDetectorBody    `json:"custom"`
	}
	if code := h.do(t, http.MethodGet, "/api/v1/dlp/detectors", nil, &listed); code != http.StatusOK ||
		len(listed.Custom) != 1 || listed.Custom[0].ID != created.ID || len(listed.Detectors) == 0 {
		t.Errorf("list: %d %+v", code, listed)
	}

	// --- editing it -------------------------------------------------------
	path := "/api/v1/dlp/detectors/" + created.ID
	bad = apiError{}
	if code := h.do(t, http.MethodPatch, path, map[string]any{"expectedVersion": 9, "description": "x"}, &bad); code != http.StatusConflict ||
		!slices.Contains(bad.codes(), any(conflictVersionCode)) || !slices.Contains(bad.codes(), any(float64(1))) {
		t.Errorf("a stale version: %d %+v", code, bad)
	}
	if code := h.do(t, http.MethodPatch, path, map[string]any{"description": "x"}, nil); code != http.StatusUnprocessableEntity {
		t.Errorf("no expectedVersion: %d", code)
	}
	bad = apiError{}
	if code := h.do(t, http.MethodPatch, path, map[string]any{"expectedVersion": 1, "name": "renamed"}, &bad); code != http.StatusUnprocessableEntity ||
		len(bad.Errors) == 0 || bad.Errors[0].Location != "body.name" {
		t.Errorf("a rename: %d %+v", code, bad)
	}
	var edited customDetectorBody
	if code := h.do(t, http.MethodPatch, path, map[string]any{"expectedVersion": 1, "description": "Contract ids, six digits"}, &edited); code != http.StatusOK ||
		edited.Version != 2 {
		t.Fatalf("edit: %d %+v", code, edited)
	}
	if revs := h.history(t, path); len(revs) != 2 || revs[0].Action != "update" || revs[1].Action != "create" {
		t.Errorf("history: %+v", revs)
	}

	// --- a policy that names it, on a real call ---------------------------
	var rule struct {
		ID string `json:"id"`
	}
	policy := map[string]any{"name": "Contracts", "connectorId": s.conn, "scan": "both",
		"detectors": []string{"custom:contract_id"}, "action": "refuse", "enabled": true}
	if code := h.do(t, http.MethodPost, "/api/v1/dlp/policies", policy, &rule); code != http.StatusCreated {
		t.Fatalf("policy: %d", code)
	}
	call := func() (string, bool) {
		return h.callText(t, s.server, s.key, "fake_get_item", map[string]any{"id": "renew " + contractID})
	}
	// The tool-call path reads through a reader of its own, as another
	// replica would; the listener is what tells it.
	var text string
	eventually(t, 5*time.Second, "the call is refused", func() bool {
		var isErr bool
		text, isErr = call()
		return isErr && strings.Contains(text, "custom:contract_id")
	})
	if strings.Contains(text, contractID) {
		t.Errorf("the refusal quotes the value: %q", text)
	}
	var detectorName string
	var matches int
	var paths []string
	h.bypass(t, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT detector, matches, paths FROM dlp_findings
			WHERE organization_id = $1 AND action = 'refuse' LIMIT 1`, s.orgID).Scan(&detectorName, &matches, &paths)
	})
	if detectorName != "custom:contract_id" || matches != 1 || !slices.Equal(paths, []string{"$.arguments.id"}) {
		t.Errorf("finding: detector %q, %d matches at %v", detectorName, matches, paths)
	}

	// Masking instead: the upstream is sent the token, and echoes it (the
	// result's JSON escapes the angle brackets).
	policy["action"] = "mask"
	if code := h.do(t, http.MethodPut, "/api/v1/dlp/policies/"+rule.ID, policy, nil); code != http.StatusOK {
		t.Fatalf("policy to mask: %d", code)
	}
	var isErr bool
	eventually(t, 5*time.Second, "the call is masked", func() bool {
		text, isErr = call()
		return !isErr && strings.Contains(text, "redacted:custom:contract_id") && !strings.Contains(text, contractID)
	})

	// --- deleting it ------------------------------------------------------
	bad = apiError{}
	if code := h.do(t, http.MethodDelete, path, nil, &bad); code != http.StatusConflict || !slices.Contains(bad.codes(), any("in_use")) {
		t.Fatalf("delete while in use: %d %+v", code, bad)
	}
	named := false
	for _, e := range bad.Errors {
		if e.Location == "references.dlpPolicies" && e.Message == "Contracts" && e.Value == rule.ID {
			named = true
		}
	}
	if !named {
		t.Errorf("the refusal does not name the policy: %+v", bad)
	}
	if code := h.do(t, http.MethodDelete, path+"?force=true", nil, nil); code != http.StatusNoContent {
		t.Fatalf("forced delete: %d", code)
	}
	var after struct {
		Detectors []string `json:"detectors"`
		Enabled   bool     `json:"enabled"`
	}
	if code := h.do(t, http.MethodGet, "/api/v1/dlp/policies/"+rule.ID, nil, &after); code != http.StatusOK ||
		len(after.Detectors) != 0 || after.Enabled {
		t.Errorf("the policy after a forced delete: %d %+v", code, after)
	}
	if code := h.do(t, http.MethodGet, path, nil, nil); code != http.StatusNotFound {
		t.Errorf("get after delete: %d", code)
	}
}

// conflictVersionCode is the machine code of a stale write.
const conflictVersionCode = "version_conflict"

// TestDLPCustomDetectorPermissions: reading asks for what reading the
// policies asks for, writing and testing for dlp:manage, and a write from
// a browser session for a recent sign-in.
func TestDLPCustomDetectorPermissions(t *testing.T) {
	h := start(t)
	admin := h.register(t, "E2E DLP detector permissions")
	dropOrgs(t, h, admin.Org.ID)
	viewer := h.member(t, admin.Org.ID, "role_viewer")

	body := map[string]any{"name": "contract_id", "pattern": `CN-\d{6}`}
	if code := viewer.do(t, http.MethodGet, "/api/v1/dlp/detectors", nil, nil); code != http.StatusOK {
		t.Errorf("a viewer reading: %d", code)
	}
	if code := viewer.do(t, http.MethodPost, "/api/v1/dlp/detectors", body, nil); code != http.StatusForbidden {
		t.Errorf("a viewer creating: %d", code)
	}
	if code := viewer.do(t, http.MethodPost, "/api/v1/dlp/detectors/test",
		map[string]any{"pattern": `CN-\d{6}`, "samples": []string{"x"}}, nil); code != http.StatusForbidden {
		t.Errorf("a viewer testing: %d", code)
	}

	var created customDetectorBody
	if code := h.do(t, http.MethodPost, "/api/v1/dlp/detectors", body, &created); code != http.StatusCreated {
		t.Fatalf("create as the owner: %d", code)
	}
	if code := viewer.do(t, http.MethodGet, "/api/v1/dlp/detectors/"+created.ID, nil, nil); code != http.StatusOK {
		t.Errorf("a viewer reading one: %d", code)
	}
	if code := viewer.do(t, http.MethodPatch, "/api/v1/dlp/detectors/"+created.ID,
		map[string]any{"expectedVersion": 1, "enabled": false}, nil); code != http.StatusForbidden {
		t.Errorf("a viewer editing: %d", code)
	}
	if code := viewer.do(t, http.MethodDelete, "/api/v1/dlp/detectors/"+created.ID, nil, nil); code != http.StatusForbidden {
		t.Errorf("a viewer deleting: %d", code)
	}

	// A session that signed in too long ago may still read and test, but
	// not write.
	h.ageSessions(t, admin.User.ID)
	var refused apiError
	if code := h.do(t, http.MethodPatch, "/api/v1/dlp/detectors/"+created.ID,
		map[string]any{"expectedVersion": 1, "enabled": false}, &refused); code != http.StatusForbidden || !refused.hasCode("reauth_required") {
		t.Errorf("a stale session's edit: %d %+v", code, refused)
	}
	if code := h.do(t, http.MethodDelete, "/api/v1/dlp/detectors/"+created.ID, nil, nil); code != http.StatusForbidden {
		t.Errorf("a stale session's delete: %d", code)
	}
	if code := h.do(t, http.MethodPost, "/api/v1/dlp/detectors/test",
		map[string]any{"pattern": `CN-\d{6}`, "samples": []string{"x"}}, nil); code != http.StatusOK {
		t.Errorf("a stale session's test: %d", code)
	}
}
