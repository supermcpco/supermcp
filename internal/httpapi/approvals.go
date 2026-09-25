package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/governance"
)

// --- approvals -------------------------------------------------------------

// The queue a person works through, and the rules that fill it.
//
// Two permissions, and they are deliberately different people:
// approvals:request is held by whoever a tool call is made on behalf of,
// and approvals:decide by whoever is allowed to agree to one. The service
// refuses a decision by the person who asked for it, so the two can be
// held by one account without that account being able to wave its own
// calls through.
//
// The arguments of a request are sealed at rest and are opened only for
// the single-request view: they are the reason the call is worth
// approving, and an approver who cannot see what they are agreeing to is
// a rubber stamp. Opening them is recorded.
//
// The permission is checked twice on anything about one request: once for
// the principal, and again against the tool the request names, so a role
// that may approve one connector's calls cannot approve another's.

type approvalListInput struct {
	State string `query:"state" enum:"pending,approved,rejected,expired,cancelled,consumed,any" default:"pending"`
	Mine  bool   `query:"mine" doc:"Only the requests you raised"`
	Limit int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
}

type approvalListOutput struct {
	Body struct {
		Approvals []governance.ApprovalRequest `json:"approvals" nullable:"false"`
	}
}

type approvalIDInput struct {
	ID string `path:"id"`
}

type approvalDecisionInput struct {
	ID   string `path:"id"`
	Body struct {
		Reason string `json:"reason,omitempty" maxLength:"2000" doc:"Why, for the record"`
	}
}

type approvalRefusalInput struct {
	ID   string `path:"id"`
	Body struct {
		Reason string `json:"reason" minLength:"1" maxLength:"2000" doc:"Why this call may not run; the model is told"`
	}
}

// approvalPolicyBody is a rule as a screen sends it. Enabled is a pointer
// so that leaving it out means on: a rule someone has just written is one
// they mean to apply.
type approvalPolicyBody struct {
	Name       string                         `json:"name" minLength:"1" maxLength:"200"`
	Scope      string                         `json:"scope,omitempty" enum:"organization,server,connector,tool" default:"organization"`
	ScopeID    string                         `json:"scopeId,omitempty" doc:"The server, connector or tool the rule applies to"`
	Trigger    string                         `json:"trigger" enum:"destructive,tool,condition"`
	ToolName   string                         `json:"toolName,omitempty" doc:"Required when the trigger is a named tool"`
	Conditions []governance.ApprovalCondition `json:"conditions,omitempty" doc:"Required when the trigger is a condition; all of them have to hold"`
	Effect     string                         `json:"effect,omitempty" enum:"require,allow" default:"require" doc:"allow narrows a broader rule"`
	TTL        int                            `json:"ttlSeconds,omitempty" minimum:"60" maximum:"604800" doc:"How long the answer has, and then how long it is good for"`
	Enabled    *bool                          `json:"enabled,omitempty"`
}

type approvalPolicyCreateInput struct {
	Body approvalPolicyBody
}

type approvalPolicyUpdateInput struct {
	ID   string `path:"id"`
	Body approvalPolicyBody
}

type approvalPolicyOutput struct {
	Body governance.ApprovalPolicy
}

type approvalPoliciesOutput struct {
	Body struct {
		Policies []governance.ApprovalPolicy `json:"policies" nullable:"false"`
	}
}

func (d Deps) approvalRoutes(api huma.API) {
	d.approvalQueueRoutes(api)
	d.approvalDecisionRoutes(api)
	d.approvalPolicyRoutes(api)
}

func (d Deps) approvalQueueRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "approvals-list", Method: http.MethodGet,
		Path: "/api/v1/approvals", Summary: "List the tool calls waiting on a person",
		Tags: []string{"approvals"}, Security: sessionSecurity},
		func(ctx context.Context, in *approvalListInput) (*approvalListOutput, error) {
			// Reading your own requests is part of asking for them;
			// reading everybody's is the approver's queue.
			perm := authz.ApprovalsDecide
			if in.Mine {
				perm = authz.ApprovalsRequest
			}
			p, err := d.require(ctx, perm, authz.Resource{})
			if err != nil {
				return nil, err
			}
			svc := d.approvals()
			if svc == nil {
				return nil, errApprovalsUnconfigured
			}
			requester := ""
			if in.Mine {
				requester = p.ID
			}
			state := governance.State(in.State)
			if in.State == "any" {
				state = ""
			}
			list, err := svc.List(ctx, p.OrgID, state, requester, in.Limit)
			if err != nil {
				return nil, err
			}
			out := &approvalListOutput{}
			out.Body.Approvals = list
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "approvals-get", Method: http.MethodGet,
		Path: "/api/v1/approvals/{id}", Summary: "Read one request, including the arguments it would run",
		Tags: []string{"approvals"}, Security: sessionSecurity},
		func(ctx context.Context, in *approvalIDInput) (*struct{ Body governance.ApprovalRequest }, error) {
			p, svc, r, err := d.approvalFor(ctx, in.ID, authz.ApprovalsDecide)
			if err != nil {
				return nil, err
			}
			opened, err := svc.Open(ctx, p.OrgID, r.ID)
			if err != nil {
				return nil, approvalErr(err)
			}
			// Unsealing the arguments is the privileged part of this
			// screen, so it is recorded whether or not anyone goes on to
			// decide anything.
			d.emit(ctx, audit.Event{Category: audit.CategoryGovernan, Action: "approval.arguments.read",
				Outcome: audit.Success, TargetKind: "approval_request", TargetID: r.ID, TargetDisplay: r.ToolName})
			return &struct{ Body governance.ApprovalRequest }{Body: *opened}, nil
		})
}

func (d Deps) approvalDecisionRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "approvals-approve", Method: http.MethodPost,
		Path: "/api/v1/approvals/{id}/approve", Summary: "Agree to a tool call",
		Tags: []string{"approvals"}, Security: sessionSecurity},
		func(ctx context.Context, in *approvalDecisionInput) (*struct{ Body governance.ApprovalRequest }, error) {
			return d.decideApproval(ctx, in.ID, governance.Decision{Approve: true, Reason: in.Body.Reason}, "approval.approve")
		})

	huma.Register(api, huma.Operation{OperationID: "approvals-reject", Method: http.MethodPost,
		Path: "/api/v1/approvals/{id}/reject", Summary: "Refuse a tool call",
		Tags: []string{"approvals"}, Security: sessionSecurity},
		func(ctx context.Context, in *approvalRefusalInput) (*struct{ Body governance.ApprovalRequest }, error) {
			return d.decideApproval(ctx, in.ID, governance.Decision{Reason: in.Body.Reason}, "approval.reject")
		})

	huma.Register(api, huma.Operation{OperationID: "approvals-cancel", Method: http.MethodPost,
		Path: "/api/v1/approvals/{id}/cancel", Summary: "Withdraw a request you raised",
		Tags: []string{"approvals"}, Security: sessionSecurity},
		func(ctx context.Context, in *approvalDecisionInput) (*struct{ Body governance.ApprovalRequest }, error) {
			p, err := d.require(ctx, authz.ApprovalsRequest, authz.Resource{})
			if err != nil {
				return nil, err
			}
			svc := d.approvals()
			if svc == nil {
				return nil, errApprovalsUnconfigured
			}
			before, err := svc.Get(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, approvalErr(err)
			}
			after, err := svc.Cancel(ctx, p.OrgID, in.ID, p.ID, in.Body.Reason)
			if err != nil {
				d.adminFailed(ctx, "approval.cancel", "approval_request", in.ID, err)
				return nil, approvalErr(err)
			}
			d.admin(ctx, "approval.cancel", "approval_request", after.ID, after.ToolName, audit.Changes(before, after))
			return &struct{ Body governance.ApprovalRequest }{Body: *after}, nil
		})
}

// decideApproval is the whole of approving and refusing: the two differ
// in one field and in the sentence the model is eventually shown, and
// splitting them would duplicate the permission check that matters.
func (d Deps) decideApproval(ctx context.Context, id string, decision governance.Decision, action string) (*struct{ Body governance.ApprovalRequest }, error) {
	// Agreeing runs a tool call somebody else asked for, under their
	// name; refusing only stops one. So only agreeing needs a recent
	// sign-in, checked before the request is looked up, like the other
	// guarded operations.
	if decision.Approve {
		if _, err := d.requireFresh(ctx, authz.ApprovalsDecide, authz.Resource{}); err != nil {
			return nil, err
		}
	}
	p, svc, before, err := d.approvalFor(ctx, id, authz.ApprovalsDecide)
	if err != nil {
		return nil, err
	}
	decision.ActorID, decision.ActorDisplay = p.ID, p.Email
	after, err := svc.Decide(ctx, p.OrgID, id, decision)
	if err != nil {
		d.adminFailed(ctx, action, "approval_request", id, err)
		return nil, approvalErr(err)
	}
	d.admin(ctx, action, "approval_request", after.ID, after.ToolName, audit.Changes(before, after))
	return &struct{ Body governance.ApprovalRequest }{Body: *after}, nil
}

func (d Deps) approvalPolicyRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "approval-policies-list", Method: http.MethodGet,
		Path: "/api/v1/approval-policies", Summary: "List the rules that decide which calls need a person",
		Tags: []string{"approvals"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*approvalPoliciesOutput, error) {
			p, err := d.require(ctx, authz.ApprovalsDecide, authz.Resource{})
			if err != nil {
				return nil, err
			}
			svc := d.approvals()
			if svc == nil {
				return nil, errApprovalsUnconfigured
			}
			list, err := svc.Policies(ctx, p.OrgID)
			if err != nil {
				return nil, err
			}
			out := &approvalPoliciesOutput{}
			out.Body.Policies = list
			return out, nil
		})

	// Writing the rules is an organisation-wide setting rather than an
	// approver's power: someone who may agree to a call should not be able
	// to arrange for it never to be asked about again.
	huma.Register(api, huma.Operation{OperationID: "approval-policies-create", Method: http.MethodPost,
		Path: "/api/v1/approval-policies", Summary: "Add a rule", Tags: []string{"approvals"},
		Security: sessionSecurity, DefaultStatus: http.StatusCreated},
		func(ctx context.Context, in *approvalPolicyCreateInput) (*approvalPolicyOutput, error) {
			p, err := d.requireFresh(ctx, authz.OrgSettingsManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			svc := d.approvals()
			if svc == nil {
				return nil, errApprovalsUnconfigured
			}
			policy := in.Body.toPolicy()
			policy.CreatedBy = p.ID
			created, err := svc.CreatePolicy(ctx, p.OrgID, policy)
			if err != nil {
				d.adminFailed(ctx, "approval.policy.create", "approval_policy", "", err)
				return nil, approvalErr(err)
			}
			d.admin(ctx, "approval.policy.create", "approval_policy", created.ID, created.Name, audit.Created(created))
			return &approvalPolicyOutput{Body: *created}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "approval-policies-update", Method: http.MethodPut,
		Path: "/api/v1/approval-policies/{id}", Summary: "Replace a rule", Tags: []string{"approvals"},
		Security: sessionSecurity},
		func(ctx context.Context, in *approvalPolicyUpdateInput) (*approvalPolicyOutput, error) {
			p, err := d.requireFresh(ctx, authz.OrgSettingsManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			svc := d.approvals()
			if svc == nil {
				return nil, errApprovalsUnconfigured
			}
			before, err := svc.GetPolicy(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, approvalErr(err)
			}
			after, err := svc.UpdatePolicy(ctx, p.OrgID, in.ID, in.Body.toPolicy(), p.ID)
			if err != nil {
				d.adminFailed(ctx, "approval.policy.update", "approval_policy", in.ID, err)
				return nil, approvalErr(err)
			}
			d.admin(ctx, "approval.policy.update", "approval_policy", after.ID, after.Name, audit.Changes(before, after))
			return &approvalPolicyOutput{Body: *after}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "approval-policies-delete", Method: http.MethodDelete,
		Path: "/api/v1/approval-policies/{id}", Summary: "Remove a rule", Tags: []string{"approvals"},
		Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *approvalIDInput) (*struct{}, error) {
			p, err := d.requireFresh(ctx, authz.OrgSettingsManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			svc := d.approvals()
			if svc == nil {
				return nil, errApprovalsUnconfigured
			}
			before, err := svc.GetPolicy(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, approvalErr(err)
			}
			if err := svc.DeletePolicy(ctx, p.OrgID, in.ID, p.ID); err != nil {
				d.adminFailed(ctx, "approval.policy.delete", "approval_policy", in.ID, err)
				return nil, approvalErr(err)
			}
			d.admin(ctx, "approval.policy.delete", "approval_policy", before.ID, before.Name, audit.Deleted(before))
			return nil, nil //nolint:nilnil // huma's no-content shape
		})

	// The rules are read from the table on every tool call, not cached,
	// so a restore applies to the next call on every replica.
	huma.Register(api, huma.Operation{OperationID: "approval-policies-revisions-restore", Method: http.MethodPost,
		Path:    "/api/v1/approval-policies/{id}/revisions/{revision}/restore",
		Summary: "Put an approval policy back the way an earlier revision found it",
		Description: "Needs revisions:rollback and org:settings:manage, and a browser session must have signed in " +
			"within the fresh-auth window. A deleted policy is recreated under its old id.",
		Tags: []string{"approvals"}, Security: sessionSecurity},
		func(ctx context.Context, in *revisionGetInput) (*approvalPolicyOutput, error) {
			p, snapshot, err := d.snapshotToRestore(ctx, approvalPolicyRevisions, in)
			if err != nil {
				return nil, err
			}
			svc := d.approvals()
			if svc == nil {
				return nil, errApprovalsUnconfigured
			}
			var want governance.ApprovalPolicy
			if err := snapInto(snapshot, "", &want); err != nil {
				return nil, err
			}
			after, replaced, err := svc.RestorePolicy(ctx, p.OrgID, in.ID, want, p.ID)
			if err != nil {
				d.restoreFailed(ctx, approvalPolicyRevisions, in, err)
				return nil, approvalErr(err)
			}
			if replaced != nil {
				d.admin(ctx, "approval.policy.update", "approval_policy", after.ID, after.Name, audit.Changes(replaced, after))
			} else {
				d.admin(ctx, "approval.policy.create", "approval_policy", after.ID, after.Name, audit.Created(after))
			}
			d.restored(ctx, approvalPolicyRevisions, in, after.Name)
			return &approvalPolicyOutput{Body: *after}, nil
		})
}

// --- helpers ---------------------------------------------------------------

var errApprovalsUnconfigured = huma.Error503ServiceUnavailable("approvals are not configured")

// approvals builds the service from what Deps already carries. It holds
// no state of its own, so one per request costs a struct literal; what it
// buys is that this file adds nothing to the router's own wiring.
func (d Deps) approvals() *governance.Approvals {
	if d.DB == nil || d.Connectors == nil || d.Connectors.Sealer == nil || d.Connectors.NewID == nil {
		return nil
	}
	svc := governance.NewApprovals(d.DB, d.Connectors.Sealer, d.Connectors.NewID)
	if d.Audit != nil {
		svc.Audit = d.Audit
	}
	svc.Revisions = d.Revisions
	return svc
}

// approvalFor resolves the principal, the service and the request, and
// checks the permission a second time against the tool the request names.
// The first check is what the principal may do at all; the second is what
// they may do to this call, which is what makes an approver scoped to one
// connector mean anything.
func (d Deps) approvalFor(ctx context.Context, id string, perm authz.Permission) (*authz.Principal, *governance.Approvals, *governance.ApprovalRequest, error) {
	p, err := d.require(ctx, perm, authz.Resource{})
	if err != nil {
		return nil, nil, nil, err
	}
	svc := d.approvals()
	if svc == nil {
		return nil, nil, nil, errApprovalsUnconfigured
	}
	r, err := svc.Get(ctx, p.OrgID, id)
	if err != nil {
		return nil, nil, nil, approvalErr(err)
	}
	res := authz.Resource{OrgID: p.OrgID, ServerID: r.ServerID, ConnectorID: r.ConnectorID, ToolID: r.ToolID}
	if err := d.Authz.Require(ctx, perm, res); err != nil {
		d.denied(ctx, perm, res, err.Error())
		return nil, nil, nil, huma.Error403Forbidden(err.Error())
	}
	return p, svc, r, nil
}

func (b approvalPolicyBody) toPolicy() governance.ApprovalPolicy {
	p := governance.ApprovalPolicy{
		Name:       b.Name,
		Scope:      governance.Scope(orString(b.Scope, string(governance.ScopeOrganization))),
		ScopeID:    b.ScopeID,
		Trigger:    governance.Trigger(b.Trigger),
		ToolName:   b.ToolName,
		Conditions: b.Conditions,
		Effect:     governance.Effect(orString(b.Effect, string(governance.EffectRequire))),
		TTL:        b.TTL,
		Enabled:    b.Enabled == nil || *b.Enabled,
	}
	return p
}

func orString(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func approvalErr(err error) error {
	switch {
	case errors.Is(err, governance.ErrApprovalNotFound), errors.Is(err, governance.ErrPolicyNotFound):
		return huma.Error404NotFound(err.Error())
	case errors.Is(err, governance.ErrSelfDecision), errors.Is(err, governance.ErrNotRequester):
		return huma.Error403Forbidden(err.Error())
	case errors.Is(err, governance.ErrAlreadyDecided), errors.Is(err, governance.ErrRequestExpired):
		return huma.Error409Conflict(err.Error())
	case errors.Is(err, governance.ErrTooManyPending):
		return huma.Error429TooManyRequests(err.Error())
	case errors.Is(err, governance.ErrInvalidPolicy):
		return huma.Error422UnprocessableEntity(err.Error())
	}
	return err
}
