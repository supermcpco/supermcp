package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/governance"
	"github.com/supermcpco/supermcp/internal/mcpserver"
)

// Asking the person behind the client about a call held for approval.
//
// A held call comes back at once naming the request it raised; that does
// not change. On a stateful session whose client said at initialise that
// it can put a question to its user, the server first asks that user,
// through elicitation/create, whether they meant the call. Confirming is
// recorded on the request for the approver to read and approves nothing:
// someone else still has to. Declining withdraws the request. No answer
// within the time allowed leaves everything as it would have been without
// the question; so does dismissing it, or submitting it without the
// confirmation ticked, since neither is a person saying no.
//
// The question names the tool and the request and nothing else. The
// arguments are what the request sealed, and the client's user is not
// necessarily someone who may read them in this form; secrets never reach
// a tool call's result, let alone a question about one.

// defaultElicitationTimeout is how long a held call waits for an answer
// when Deps says nothing.
const defaultElicitationTimeout = 45 * time.Second

// answerMargin is kept between the end of the wait and the request's own
// deadline, so the held result can still be written before the router
// gives up on the request.
const answerMargin = 5 * time.Second

// elicitNote bounds the note field the client is offered.
const elicitNote = governance.MaxAcknowledgement

// withdrawnReason is what a request withdrawn from the client records.
const withdrawnReason = "Withdrawn from the MCP client: the person asked to confirm the call declined."

// Drain stops waiting for answers. The server calls it when it has been
// told to stop, before the listener drains, so a call waiting on a person
// returns at once, as it would without the question, and does not hold
// the shutdown for the rest of the wait.
func (e *Endpoint) Drain() {
	e.drainOnce.Do(func() { close(e.draining) })
}

// canElicit reports whether a question can reach the person behind this
// call's client.
func (e *Endpoint) canElicit(server *mcpserver.Server, ss *sdk.ServerSession) bool {
	if e.Approvals == nil || server.Sessions != mcpserver.SessionsStateful || ss == nil || ss.ID() == "" {
		return false
	}
	// In JSON response mode the transport sends a server's own request on
	// the stream a GET opens, and this endpoint offers none.
	if e.JSONResponse {
		return false
	}
	params := ss.InitializeParams()
	if params == nil || params.Capabilities == nil || params.Capabilities.Elicitation == nil {
		return false
	}
	caps := params.Capabilities.Elicitation
	// A client that declared only URL elicitation cannot show a form; one
	// that declared neither is taken to mean forms, as the SDK does.
	return caps.Form != nil || caps.URL == nil
}

// confirmHeld asks about a call the executor held for approval, and
// returns the result the model is given.
func (e *Endpoint) confirmHeld(ctx context.Context, req *sdk.CallToolRequest, server *mcpserver.Server, p *authz.Principal,
	notice *governance.Notice, held *sdk.CallToolResult,
) *sdk.CallToolResult {
	if notice.State != governance.StatePending || !e.canElicit(server, req.Session) {
		return held
	}
	before, err := e.Approvals.Get(ctx, server.OrgID, notice.RequestID)
	if err != nil || before.AcknowledgedAt != nil || before.RequestedBy != p.ID {
		// Asked already, or not this caller's to answer: the same call
		// repeated is not a new question.
		return held
	}

	answer, err := e.elicit(ctx, req.Session, notice)
	if err != nil {
		e.debug(ctx, "no answer to the approval question; the call stays held", "request", notice.RequestID, "err", err)
		return held
	}
	confirmed, _ := answer.Content["confirm"].(bool)
	switch {
	case answer.Action == "accept" && confirmed:
		note, _ := answer.Content["note"].(string)
		if _, err := e.Approvals.Acknowledge(ctx, server.OrgID, notice.RequestID, p.ID, note); err != nil {
			e.debug(ctx, "the confirmation could not be recorded", "request", notice.RequestID, "err", err)
			return held
		}
		acked := *notice
		acked.Acknowledged = true
		return &sdk.CallToolResult{IsError: true, StructuredContent: &acked, Content: []sdk.Content{&sdk.TextContent{
			Text: textOf(held) + "\n\nThe person you are working for confirmed that they asked for this call, and the approver " +
				"can see that. It still needs someone else to approve it.",
		}}}
	case answer.Action != "decline":
		// Dismissed, or submitted without confirming: no answer.
		return held
	}

	// Declined: the person says they did not ask for the call, so it does
	// not wait for anyone. A confirmation that got there first stands.
	after, err := e.Approvals.Withdraw(ctx, server.OrgID, notice.RequestID, p.ID, withdrawnReason)
	if err != nil {
		e.debug(ctx, "the request could not be withdrawn", "request", notice.RequestID, "err", err)
		return held
	}
	e.audit(ctx, p, audit.Event{OrgID: server.OrgID, Category: audit.CategoryAdmin, Action: "approval.cancel",
		Outcome: audit.Success, TargetKind: "approval_request", TargetID: after.ID, TargetDisplay: after.ToolName,
		Diff: audit.Changes(before, after), Meta: map[string]any{"via": "elicitation", "answer": answer.Action}})
	withdrawn := *notice
	withdrawn.Status, withdrawn.State, withdrawn.RetryWith, withdrawn.Reason = "approval_cancelled", governance.StateCancelled, "", withdrawnReason
	return &sdk.CallToolResult{IsError: true, StructuredContent: &withdrawn, Content: []sdk.Content{&sdk.TextContent{
		Text: fmt.Sprintf("Request %s was withdrawn: the person you are working for declined this call when asked. "+
			"Nothing ran. Do not repeat the call unless they ask for it again.", notice.RequestID),
	}}}
}

// elicit puts the question and waits for the answer, for no longer than
// the endpoint allows, the call's own deadline, or the server draining.
func (e *Endpoint) elicit(ctx context.Context, ss *sdk.ServerSession, notice *governance.Notice) (*sdk.ElicitResult, error) {
	wait := e.ElicitationTimeout
	if wait <= 0 {
		wait = defaultElicitationTimeout
	}
	if deadline, ok := ctx.Deadline(); ok {
		wait = min(wait, time.Until(deadline)-answerMargin)
	}
	if wait <= 0 {
		return nil, errors.New("no time left before the request's deadline to ask")
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	// Owned by this call: it ends when the wait does, which the deferred
	// cancel guarantees, or cuts the wait short when the server drains.
	go func() {
		select {
		case <-e.draining:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ss.Elicit(ctx, &sdk.ElicitParams{
		Mode: "form",
		Message: fmt.Sprintf("A call to %s is waiting for someone to approve it (request %s). Did you ask for it? "+
			"Confirming does not approve it: it tells the approver you meant it. Declining withdraws the request.",
			notice.Tool, notice.RequestID),
		RequestedSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"confirm": map[string]any{"type": "boolean", "title": "I asked for this call", "default": true},
				"note": map[string]any{"type": "string", "title": "Note for the approver", "maxLength": elicitNote,
					"description": "Optional. Why the call is needed, for whoever approves it."},
			},
			"required": []string{"confirm"},
		},
	})
}

func (e *Endpoint) audit(ctx context.Context, p *authz.Principal, ev audit.Event) {
	if e.Audit == nil {
		return
	}
	e.Audit.Emit(ctx, audit.FromPrincipal(ev, p))
}

func (e *Endpoint) debug(ctx context.Context, msg string, args ...any) {
	if e.Log != nil {
		e.Log.DebugContext(ctx, msg, args...)
	}
}

// textOf is the text of a result's first content, which is where the
// executor puts what the model is told.
func textOf(r *sdk.CallToolResult) string {
	var parts []string
	for _, c := range r.Content {
		if t, ok := c.(*sdk.TextContent); ok {
			parts = append(parts, t.Text)
		}
	}
	return strings.Join(parts, "\n")
}
