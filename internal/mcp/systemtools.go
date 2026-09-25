package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/governance"
	"github.com/supermcpco/supermcp/internal/mcpserver"
)

// The tools every server has for following up a call held for approval:
// what became of the request, and withdrawing it. They belong to
// supermcp, not to a connector, and work the same on both session modes.
//
// They can be called on every server, but a server lists them only when
// a rule that asks for a person could hold one of its calls: anywhere
// else they would be two more tools for a model to read about and never
// use. The hidden-tool guard lets them through either way.
//
// Both act only on the caller's own requests. Someone else's, or one that
// does not exist, is answered the same way, so a caller learns nothing
// about requests that are not theirs.

// The system tools' names. A connector tool with either name is shadowed.
const (
	ToolApprovalStatus = "supermcp_approval_status"
	ToolApprovalCancel = "supermcp_approval_cancel"
)

func isSystemTool(name string) bool {
	return name == ToolApprovalStatus || name == ToolApprovalCancel
}

// approvalStatus is what both tools answer with.
type approvalStatus struct {
	RequestID      string     `json:"requestId"`
	State          string     `json:"state"`
	Tool           string     `json:"tool"`
	DecidedBy      string     `json:"decidedBy,omitempty"`
	DecidedAt      *time.Time `json:"decidedAt,omitempty"`
	Reason         string     `json:"reason,omitempty"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	AcknowledgedAt *time.Time `json:"acknowledgedAt,omitempty"`
}

var statusOutputSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"requestId":      map[string]any{"type": "string"},
		"state":          map[string]any{"type": "string", "enum": []string{"pending", "approved", "rejected", "expired", "cancelled", "consumed"}},
		"tool":           map[string]any{"type": "string"},
		"decidedBy":      map[string]any{"type": "string", "description": "Who approved or refused it."},
		"decidedAt":      map[string]any{"type": "string", "format": "date-time"},
		"reason":         map[string]any{"type": "string", "description": "Why it was approved, refused or withdrawn."},
		"expiresAt":      map[string]any{"type": "string", "format": "date-time"},
		"acknowledgedAt": map[string]any{"type": "string", "format": "date-time"},
	},
	"required": []string{"requestId", "state", "tool", "expiresAt"},
}

// systemTools are the two tools as tools/list shows them.
func systemTools() []*sdk.Tool {
	id := map[string]any{"type": "string", "description": "The approvalRequestId the held call returned."}
	return []*sdk.Tool{
		{
			Name: ToolApprovalStatus,
			Description: "Read what became of a tool call you made that is waiting for a person to approve it: " +
				"pending, approved, refused, expired, withdrawn or used, who decided it and when, and why.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{"requestId": id},
				"required": []string{"requestId"}},
			OutputSchema: statusOutputSchema,
			Annotations: &sdk.ToolAnnotations{Title: "Approval status", ReadOnlyHint: true, IdempotentHint: true,
				OpenWorldHint: boolPtr(false)},
		},
		{
			Name: ToolApprovalCancel,
			Description: "Withdraw a tool call you made that is still waiting for a person to approve it, " +
				"for example because it is no longer needed. Only the one who made the call can withdraw it.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{
				"requestId": id,
				"reason": map[string]any{"type": "string", "maxLength": 2000,
					"description": "Why it is withdrawn, for the record. Optional."},
			}, "required": []string{"requestId"}},
			OutputSchema: statusOutputSchema,
			Annotations: &sdk.ToolAnnotations{Title: "Withdraw approval request", DestructiveHint: boolPtr(false),
				IdempotentHint: true, OpenWorldHint: boolPtr(false)},
		},
	}
}

// systemToolCalls answers a call to a system tool before the SDK looks the
// name up, because a server that does not list them does not register
// them either. It runs after the hidden-tool guard.
func (e *Endpoint) systemToolCalls(server *mcpserver.Server) sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method != "tools/call" {
				return next(ctx, method, req)
			}
			call, ok := req.(*sdk.CallToolRequest)
			if !ok || !isSystemTool(call.Params.Name) {
				return next(ctx, method, req)
			}
			return e.systemCall(ctx, server, call)
		}
	}
}

// systemToolHandler is what a listing registers. The middleware answers
// first; this is here so the SDK has a handler to register.
func (e *Endpoint) systemToolHandler(server *mcpserver.Server) sdk.ToolHandler {
	return func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return e.systemCall(ctx, server, req)
	}
}

func (e *Endpoint) systemCall(ctx context.Context, server *mcpserver.Server, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
	p, ok := authz.From(ctx)
	if !ok || p == nil {
		return nil, errors.New("authentication required")
	}
	if e.Approvals == nil {
		return errorResult("Approvals are not configured on this instance, so there is no request to follow up."), nil
	}
	var in struct {
		RequestID string `json:"requestId"`
		Reason    string `json:"reason"`
	}
	if len(req.Params.Arguments) > 0 {
		if err := json.Unmarshal(req.Params.Arguments, &in); err != nil {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "arguments must be an object with a requestId"}
		}
	}
	in.RequestID = strings.TrimSpace(in.RequestID)
	if in.RequestID == "" {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "requestId is required"}
	}
	r, found := e.ownRequest(ctx, server, p, in.RequestID)
	if !found {
		return errorResult(fmt.Sprintf("There is no approval request %s among the calls you made.", in.RequestID)), nil
	}
	if req.Params.Name == ToolApprovalStatus {
		return statusResult(r, describe(r)), nil
	}

	if rs := []rune(in.Reason); len(rs) > 2000 {
		in.Reason = string(rs[:2000])
	}
	after, err := e.Approvals.Cancel(ctx, server.OrgID, r.ID, p.ID, in.Reason)
	if err != nil {
		e.audit(ctx, p, audit.Event{OrgID: server.OrgID, Category: audit.CategoryAdmin, Action: "approval.cancel",
			Outcome: audit.Failure, TargetKind: "approval_request", TargetID: r.ID,
			Meta: map[string]any{"error": err.Error(), "via": "mcp"}})
		if errors.Is(err, governance.ErrAlreadyDecided) || errors.Is(err, governance.ErrRequestExpired) {
			// Read again: what refused the withdrawal is the state now,
			// not the one read before it.
			if cur, gerr := e.Approvals.Get(ctx, server.OrgID, r.ID); gerr == nil {
				r = cur
			}
			res := statusResult(r, fmt.Sprintf("Request %s can no longer be withdrawn. %s", r.ID, describe(r)))
			res.IsError = true
			return res, nil
		}
		return nil, fmt.Errorf("withdraw approval request: %w", err)
	}
	e.audit(ctx, p, audit.Event{OrgID: server.OrgID, Category: audit.CategoryAdmin, Action: "approval.cancel",
		Outcome: audit.Success, TargetKind: "approval_request", TargetID: after.ID, TargetDisplay: after.ToolName,
		Diff: audit.Changes(r, after), Meta: map[string]any{"via": "mcp"}})
	return statusResult(after, fmt.Sprintf("Request %s is withdrawn. Nothing ran, and nobody will be asked to approve it.", after.ID)), nil
}

// ownRequest reads a request the caller raised and may still invoke the
// tool of. Anything else is reported as not found.
func (e *Endpoint) ownRequest(ctx context.Context, server *mcpserver.Server, p *authz.Principal, id string) (*governance.ApprovalRequest, bool) {
	if p.OrgID != server.OrgID {
		return nil, false
	}
	r, err := e.Approvals.Get(ctx, server.OrgID, id)
	if err != nil || r.RequestedBy != p.ID {
		return nil, false
	}
	// As the API checks a request against the tool it names: a caller who
	// may no longer use the tool is not told what became of the call.
	d, err := e.Authz.Evaluate(ctx, p, authz.ToolsInvoke, authz.Resource{OrgID: server.OrgID, ServerID: r.ServerID,
		ConnectorID: r.ConnectorID, ToolID: r.ToolID})
	if err != nil || !d.Allow {
		return nil, false
	}
	return r, true
}

// describe says what a request's state means for the model reading it.
func describe(r *governance.ApprovalRequest) string {
	switch r.State {
	case governance.StatePending:
		return fmt.Sprintf("Request %s for %s is still waiting for someone to approve it, until %s.",
			r.ID, r.ToolName, r.ExpiresAt.UTC().Format(time.RFC3339))
	case governance.StateApproved:
		return fmt.Sprintf("Request %s for %s was approved. Call %s again with %q set to %q to run the arguments that were approved, before %s.",
			r.ID, r.ToolName, r.ToolName, governance.ArgApprovalID, r.ID, r.ExpiresAt.UTC().Format(time.RFC3339))
	case governance.StateRejected:
		return fmt.Sprintf("Request %s for %s was refused: %s. Do not try the call again.", r.ID, r.ToolName, orNone(r.Reason))
	case governance.StateExpired:
		return fmt.Sprintf("Request %s for %s lapsed without an answer.", r.ID, r.ToolName)
	case governance.StateCancelled:
		return fmt.Sprintf("Request %s for %s was withdrawn.", r.ID, r.ToolName)
	case governance.StateConsumed:
		return fmt.Sprintf("Request %s for %s was approved and has been used.", r.ID, r.ToolName)
	}
	return fmt.Sprintf("Request %s is %s.", r.ID, r.State)
}

func statusResult(r *governance.ApprovalRequest, text string) *sdk.CallToolResult {
	return &sdk.CallToolResult{
		Content: []sdk.Content{&sdk.TextContent{Text: text}},
		StructuredContent: &approvalStatus{RequestID: r.ID, State: string(r.State), Tool: r.ToolName,
			DecidedBy: r.DecidedBy, DecidedAt: r.DecidedAt, Reason: r.Reason, ExpiresAt: r.ExpiresAt,
			AcknowledgedAt: r.AcknowledgedAt},
	}
}

func errorResult(text string) *sdk.CallToolResult {
	return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: text}}}
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "no reason given"
	}
	return s
}

// followUpHint is added to a held call's result on a server that has the
// system tools, so the model knows it can check on the request.
const followUpHint = "\n\nTo see whether it has been answered, call " + ToolApprovalStatus + " with this request id; to withdraw it, call " + ToolApprovalCancel + "."
