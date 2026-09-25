package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/dlp"
)

// --- data-loss prevention --------------------------------------------------

// Reading the policies is part of reading the configuration, so it asks
// for the same permission a connector does. Writing one changes what
// leaves the instance and what a model is shown, so it asks for dlp:manage
// and is recorded like any other administrative change.
//
// The preview endpoint runs the detectors over a sample an administrator
// pastes in, so a rule can be seen working before it is turned on. It
// writes nothing, but it asks for dlp:manage anyway: it is the tool for
// tuning a policy, and the sample comes from whoever is holding it.

// previewMaxBytes caps the sample a preview will read. It is larger than
// the default scan window on purpose, so an administrator can see the
// truncation boundary behave rather than read about it.
const previewMaxBytes = 256 << 10

type dlpPolicyBody struct {
	Name        string   `json:"name" maxLength:"120" doc:"What this rule is for, in the administrator's own words"`
	ConnectorID string   `json:"connectorId,omitempty" doc:"Narrow the rule to one connector; empty covers the organisation"`
	ToolID      string   `json:"toolId,omitempty" doc:"Narrow the rule to one tool; needs connectorId as well"`
	Scan        string   `json:"scan" enum:"arguments,result,both" default:"both" doc:"Which half of a tool call to read"`
	Detectors   []string `json:"detectors,omitempty" doc:"Which detectors run; empty means all of them"`
	Action      string   `json:"action" enum:"allow,mask,refuse" doc:"Record what was found, mask it, or refuse the call"`
	Enabled     bool     `json:"enabled" default:"true"`
	MaxBytes    int      `json:"maxBytes,omitempty" minimum:"0" maximum:"4194304" doc:"How much of a value to read; zero takes the built-in cap"`
}

type dlpPolicyListOutput struct {
	Body struct {
		Policies []dlp.ScanPolicy `json:"policies" nullable:"false"`
	}
}

type dlpPolicyOutput struct {
	Body dlp.ScanPolicy
}

type dlpPolicyCreateInput struct {
	Body dlpPolicyBody
}

type dlpPolicyUpdateInput struct {
	ID   string `path:"id"`
	Body dlpPolicyBody
}

type dlpPolicyGetInput struct {
	ID string `path:"id"`
}

type dlpDetectorOutput struct {
	Body struct {
		Detectors []dlp.DetectorInfo `json:"detectors" nullable:"false"`
	}
}

type dlpPreviewInput struct {
	Body struct {
		Sample    string   `json:"sample" maxLength:"262144" doc:"Text to run the detectors over"`
		Detectors []string `json:"detectors,omitempty" doc:"Which detectors run; empty means all of them"`
		Action    string   `json:"action" enum:"allow,mask,refuse" default:"mask" doc:"What the policy would do"`
	}
}

type dlpPreviewOutput struct {
	Body struct {
		Findings  []dlp.Finding `json:"findings" nullable:"false"`
		Matches   int           `json:"matches"`
		Bytes     int           `json:"bytes" doc:"How much of the sample was read"`
		Truncated bool          `json:"truncated" doc:"The budget ran out before the sample did"`
		Refused   bool          `json:"refused" doc:"A refusing policy would have stopped this call"`
		Masked    string        `json:"masked,omitempty" doc:"The sample as a masking policy would leave it"`
	}
}

func (b dlpPolicyBody) policy() dlp.ScanPolicy {
	return dlp.ScanPolicy{Name: b.Name, ConnectorID: b.ConnectorID, ToolID: b.ToolID,
		Scan: dlp.Stage(b.Scan), Detectors: b.Detectors, Action: dlp.Action(b.Action),
		Enabled: b.Enabled, MaxBytes: b.MaxBytes}
}

func (d Deps) dlpRoutes(api huma.API) {
	// The routes share the tool-call path's reader, so a policy written
	// here drops that cache on this replica before the response goes out.
	// Other replicas hear of it from the database (see
	// internal/invalidation).
	policies := d.DLP
	if policies == nil {
		policies = dlp.NewPolicies(d.DB, nil)
		if policies != nil && d.Revisions != nil {
			policies.Revisions = d.Revisions
		}
	}

	huma.Register(api, huma.Operation{OperationID: "dlp-detectors", Method: http.MethodGet,
		Path: "/api/v1/dlp/detectors", Summary: "List the built-in detectors, and what each one lets through",
		Tags: []string{"dlp"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*dlpDetectorOutput, error) {
			if _, err := d.require(ctx, authz.ConnectorsRead, authz.Resource{}); err != nil {
				return nil, err
			}
			out := &dlpDetectorOutput{}
			out.Body.Detectors = dlp.Catalogue()
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "dlp-policies-list", Method: http.MethodGet,
		Path: "/api/v1/dlp/policies", Summary: "List the data-loss prevention policies",
		Tags: []string{"dlp"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*dlpPolicyListOutput, error) {
			p, err := d.require(ctx, authz.ConnectorsRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if policies == nil {
				return nil, huma.Error503ServiceUnavailable("data-loss prevention is not configured")
			}
			list, err := policies.List(ctx, p.OrgID)
			if err != nil {
				return nil, err
			}
			out := &dlpPolicyListOutput{}
			out.Body.Policies = list
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "dlp-policy-get", Method: http.MethodGet,
		Path: "/api/v1/dlp/policies/{id}", Summary: "Read one data-loss prevention policy",
		Tags: []string{"dlp"}, Security: sessionSecurity},
		func(ctx context.Context, in *dlpPolicyGetInput) (*dlpPolicyOutput, error) {
			p, err := d.require(ctx, authz.ConnectorsRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if policies == nil {
				return nil, huma.Error503ServiceUnavailable("data-loss prevention is not configured")
			}
			got, err := policies.Get(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, dlpErr(err)
			}
			return &dlpPolicyOutput{Body: got}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "dlp-policy-create", Method: http.MethodPost,
		Path: "/api/v1/dlp/policies", Summary: "Add a data-loss prevention policy",
		Tags: []string{"dlp"}, Security: sessionSecurity, DefaultStatus: http.StatusCreated},
		func(ctx context.Context, in *dlpPolicyCreateInput) (*dlpPolicyOutput, error) {
			p, err := d.requireFresh(ctx, authz.DLPManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if policies == nil {
				return nil, huma.Error503ServiceUnavailable("data-loss prevention is not configured")
			}
			want := in.Body.policy()
			want.CreatedBy = p.ID
			got, err := policies.Create(ctx, p.OrgID, want)
			if err != nil {
				d.adminFailed(ctx, "dlp.policy.create", "dlp_policy", "", err)
				return nil, dlpErr(err)
			}
			d.admin(ctx, "dlp.policy.create", "dlp_policy", got.ID, got.Name, audit.Created(got))
			return &dlpPolicyOutput{Body: got}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "dlp-policy-update", Method: http.MethodPut,
		Path: "/api/v1/dlp/policies/{id}", Summary: "Change a data-loss prevention policy",
		Tags: []string{"dlp"}, Security: sessionSecurity},
		func(ctx context.Context, in *dlpPolicyUpdateInput) (*dlpPolicyOutput, error) {
			p, err := d.requireFresh(ctx, authz.DLPManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if policies == nil {
				return nil, huma.Error503ServiceUnavailable("data-loss prevention is not configured")
			}
			// The before is read for the record, not to merge into: a PUT
			// replaces the rule, and a half-applied policy is a rule
			// nobody wrote.
			before, err := policies.Get(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, dlpErr(err)
			}
			got, err := policies.Update(ctx, p.OrgID, in.ID, in.Body.policy(), p.ID)
			if err != nil {
				d.adminFailed(ctx, "dlp.policy.update", "dlp_policy", in.ID, err)
				return nil, dlpErr(err)
			}
			d.admin(ctx, "dlp.policy.update", "dlp_policy", got.ID, got.Name, audit.Changes(before, got))
			return &dlpPolicyOutput{Body: got}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "dlp-policy-delete", Method: http.MethodDelete,
		Path: "/api/v1/dlp/policies/{id}", Summary: "Remove a data-loss prevention policy",
		Tags: []string{"dlp"}, Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *dlpPolicyGetInput) (*struct{}, error) {
			p, err := d.requireFresh(ctx, authz.DLPManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if policies == nil {
				return nil, huma.Error503ServiceUnavailable("data-loss prevention is not configured")
			}
			before, err := policies.Get(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, dlpErr(err)
			}
			if err := policies.Delete(ctx, p.OrgID, in.ID, p.ID); err != nil {
				d.adminFailed(ctx, "dlp.policy.delete", "dlp_policy", in.ID, err)
				return nil, dlpErr(err)
			}
			d.admin(ctx, "dlp.policy.delete", "dlp_policy", before.ID, before.Name, audit.Deleted(before))
			return nil, nil //nolint:nilnil // huma's no-content shape
		})

	// A restore goes through the reader the tool-call path uses, like an
	// edit: this replica's cache is dropped before the response goes out,
	// and the table's trigger tells every other replica on commit.
	huma.Register(api, huma.Operation{OperationID: "dlp-policies-revisions-restore", Method: http.MethodPost,
		Path:    "/api/v1/dlp/policies/{id}/revisions/{revision}/restore",
		Summary: "Put a data-loss prevention policy back the way an earlier revision found it",
		Description: "Needs revisions:rollback and dlp:manage, and a browser session must have signed in within " +
			"the fresh-auth window. A deleted policy is recreated under its old id.",
		Tags: []string{"dlp"}, Security: sessionSecurity},
		func(ctx context.Context, in *revisionGetInput) (*dlpPolicyOutput, error) {
			p, snapshot, err := d.snapshotToRestore(ctx, dlpRevisions, in)
			if err != nil {
				return nil, err
			}
			if policies == nil {
				return nil, huma.Error503ServiceUnavailable("data-loss prevention is not configured")
			}
			var want dlp.ScanPolicy
			if err := snapInto(snapshot, "", &want); err != nil {
				return nil, err
			}
			before, getErr := policies.Get(ctx, p.OrgID, in.ID)
			got, err := policies.Restore(ctx, p.OrgID, in.ID, want, p.ID)
			if err != nil {
				d.restoreFailed(ctx, dlpRevisions, in, err)
				return nil, dlpErr(err)
			}
			if getErr == nil {
				d.admin(ctx, "dlp.policy.update", "dlp_policy", got.ID, got.Name, audit.Changes(before, got))
			} else {
				d.admin(ctx, "dlp.policy.create", "dlp_policy", got.ID, got.Name, audit.Created(got))
			}
			d.restored(ctx, dlpRevisions, in, got.Name)
			return &dlpPolicyOutput{Body: got}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "dlp-preview", Method: http.MethodPost,
		Path: "/api/v1/dlp/preview", Summary: "Run the detectors over a sample to see what a policy would catch",
		Tags: []string{"dlp"}, Security: sessionSecurity},
		func(ctx context.Context, in *dlpPreviewInput) (*dlpPreviewOutput, error) {
			if _, err := d.require(ctx, authz.DLPManage, authz.Resource{}); err != nil {
				return nil, err
			}
			rule := dlp.ScanPolicy{Name: "preview", Scan: dlp.StageBoth, Detectors: in.Body.Detectors,
				Action: dlp.Action(in.Body.Action), Enabled: true, MaxBytes: previewMaxBytes}
			if err := rule.Validate(); err != nil {
				return nil, dlpErr(err)
			}
			masked, res, refused := dlp.Apply(in.Body.Sample, rule.Action, rule.Options("$"))
			out := &dlpPreviewOutput{}
			out.Body.Findings = res.Findings
			if out.Body.Findings == nil {
				out.Body.Findings = []dlp.Finding{}
			}
			out.Body.Matches, out.Body.Bytes, out.Body.Truncated = res.Matches, res.Bytes, res.Truncated
			out.Body.Refused = errors.Is(refused, dlp.ErrRefused)
			// The sample is the administrator's own text, so showing it
			// back masked tells them what the rule would leave behind. A
			// refusal has nothing to show.
			if s, ok := masked.(string); ok && rule.Action == dlp.ActionMask {
				out.Body.Masked = s
			}
			return out, nil
		})
}

// dlpErr maps the package's errors to the status a caller can act on.
func dlpErr(err error) error {
	switch {
	case errors.Is(err, dlp.ErrNotFound):
		return huma.Error404NotFound(err.Error())
	case errors.Is(err, dlp.ErrInvalid):
		return huma.Error400BadRequest(err.Error())
	}
	return err
}
