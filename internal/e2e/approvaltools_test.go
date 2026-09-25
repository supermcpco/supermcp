package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// The two tools for following up a held call, through the real endpoint.

type statusWire struct {
	RequestID string `json:"requestId"`
	State     string `json:"state"`
	Tool      string `json:"tool"`
	DecidedBy string `json:"decidedBy"`
}

func systemCall(t *testing.T, sess *sdk.ClientSession, name, id string) (*sdk.CallToolResult, statusWire) {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &sdk.CallToolParams{Name: name, Arguments: map[string]any{"requestId": id}})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var st statusWire
	if res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		_ = json.Unmarshal(b, &st)
	}
	return res, st
}

func listed(t *testing.T, sess *sdk.ClientSession) map[string]bool {
	t.Helper()
	res, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, tl := range res.Tools {
		out[tl.Name] = true
	}
	return out
}

// A server no rule reaches does not list them, and they still answer.
func TestApprovalToolsAreHiddenWhereNothingIsHeld(t *testing.T) {
	f := newToolFixture(t)
	sess := f.connectMCP(t, nil)
	tools := listed(t, sess)
	if tools["supermcp_approval_status"] || tools["supermcp_approval_cancel"] {
		t.Errorf("a server no approval rule reaches lists the approval tools: %v", tools)
	}
	res, _ := systemCall(t, sess, "supermcp_approval_status", "no-such-request")
	if !res.IsError || !strings.Contains(resultText(res), "no approval request") {
		t.Errorf("status of an unknown request: %q", resultText(res))
	}
}

func TestApprovalToolsFollowUpAHeldCall(t *testing.T) {
	for _, mode := range []string{"stateless", "stateful"} {
		t.Run(mode, func(t *testing.T) {
			f := heldFixture(t, harnessOptions{})
			f.setSessions(t, mode)
			sess := f.connectMCP(t, nil)
			tools := listed(t, sess)
			if !tools["supermcp_approval_status"] || !tools["supermcp_approval_cancel"] {
				t.Fatalf("a server an approval rule reaches does not list the approval tools: %v", tools)
			}

			res, id := held(t, sess, map[string]any{"id": "1"})
			if !strings.Contains(resultText(res), "supermcp_approval_status") {
				t.Errorf("the held result does not say how to follow it up: %q", resultText(res))
			}
			res, st := systemCall(t, sess, "supermcp_approval_status", id)
			if res.IsError || st.State != "pending" || st.Tool != "fake_get_item" || st.RequestID != id {
				t.Fatalf("status of the held call: %q %+v", resultText(res), st)
			}

			// Someone else in the workspace, who may call the same tool, is
			// told there is no such request rather than what it is.
			viewer := f.member(t, "role_viewer", "org", "")
			var key struct {
				Secret string `json:"secret"`
			}
			if code := viewer.do(t, http.MethodPost, "/api/v1/api-keys", map[string]any{"name": "viewer"}, &key); code != 200 && code != 201 {
				t.Fatalf("viewer key: %d", code)
			}
			other := &toolFixture{h: f.h, srv: f.srv, key: key.Secret}
			osess := other.connectMCP(t, nil)
			for _, name := range []string{"supermcp_approval_status", "supermcp_approval_cancel"} {
				res, st := systemCall(t, osess, name, id)
				if !res.IsError || st.State != "" || !strings.Contains(resultText(res), "no approval request") {
					t.Errorf("%s on someone else's request: %q %+v", name, resultText(res), st)
				}
			}

			// An answer shows up in the status.
			approver := f.member(t, "role_approver", "org", "")
			var decided struct {
				DecidedBy string `json:"decidedBy"`
			}
			if code := approver.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/approve", map[string]any{"reason": "fine"}, &decided); code != 200 {
				t.Fatalf("approve: %d", code)
			}
			if _, st := systemCall(t, sess, "supermcp_approval_status", id); st.State != "approved" || st.DecidedBy != decided.DecidedBy {
				t.Errorf("status after approval: %+v, want approved by %s", st, decided.DecidedBy)
			}

			// A second call can be withdrawn, once.
			_, second := held(t, sess, map[string]any{"id": "2"})
			res, st = systemCall(t, sess, "supermcp_approval_cancel", second)
			if res.IsError || st.State != "cancelled" {
				t.Fatalf("withdraw: %q %+v", resultText(res), st)
			}
			if got := f.approval(t, second); got.State != "cancelled" {
				t.Errorf("the request after withdrawing: %+v", got)
			}
			res, st = systemCall(t, sess, "supermcp_approval_cancel", second)
			if !res.IsError || st.State != "cancelled" || !strings.Contains(resultText(res), "can no longer be withdrawn") {
				t.Errorf("withdrawing twice: %q %+v", resultText(res), st)
			}

			var ok, failed bool
			for _, e := range f.h.auditEvents(t, context.Background(), f.admin.Org.ID) {
				if e.Action == "approval.cancel" && e.TargetID == second && e.Meta["via"] == "mcp" {
					ok = ok || e.Outcome == "success"
					failed = failed || e.Outcome == "failure"
				}
			}
			if !ok || !failed {
				t.Errorf("the audit trail has the withdrawal %v and the refused second one %v, want both", ok, failed)
			}
			if *f.calls != 0 {
				t.Errorf("the upstream was called %d times", *f.calls)
			}
		})
	}
}
