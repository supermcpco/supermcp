package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/dlp"
)

// --- custom data-loss detectors --------------------------------------------

// A workspace's own detectors are part of its data-loss configuration, so
// they are read with the permission that reads the policies and written
// with dlp:manage and a recent sign-in, as a policy is. The test route
// writes nothing and asks for dlp:manage alone, like the preview.
//
// A detector's samples are the administrator's own text, and the test
// route answers with offsets only: nothing a pattern matched is ever
// quoted back, here or in a finding.

// conflictInUse is the code on a delete refused because policies name
// the detector.
const conflictInUse = "in_use"

type dlpDetectorCreateInput struct {
	Body struct {
		Name         string   `json:"name" maxLength:"63" doc:"Lower-case letters, digits, - and _; policies name the detector custom:<name>, and it never changes"`
		Description  string   `json:"description,omitempty" maxLength:"500"`
		Pattern      string   `json:"pattern" maxLength:"512" doc:"RE2 regular expression, 3 to 512 bytes, that cannot match the empty string"`
		Flags        string   `json:"flags,omitempty" enum:",i" doc:"i for case-insensitive"`
		MustMatch    []string `json:"mustMatch,omitempty" maxItems:"20" doc:"Samples, at most 1024 bytes each, that must each contain a match"`
		MustNotMatch []string `json:"mustNotMatch,omitempty" maxItems:"20" doc:"Samples, at most 1024 bytes each, that must contain none"`
		Enabled      bool     `json:"enabled,omitempty" default:"true"`
	}
}

type dlpDetectorUpdateInput struct {
	ID   string `path:"id"`
	Body struct {
		ExpectedVersion int64 `json:"expectedVersion" minimum:"1" doc:"The version that was read. A mismatch is a 409"`
		// Name is accepted only to be refused with a reason: sent unchanged
		// it is ignored, changed it is a 422.
		Name         *string  `json:"name,omitempty" doc:"Cannot change; sent only unchanged"`
		Description  *string  `json:"description,omitempty" maxLength:"500"`
		Pattern      *string  `json:"pattern,omitempty" maxLength:"512"`
		Flags        *string  `json:"flags,omitempty" enum:",i"`
		MustMatch    []string `json:"mustMatch,omitempty" maxItems:"20" doc:"Replaces the list when present; [] clears it"`
		MustNotMatch []string `json:"mustNotMatch,omitempty" maxItems:"20" doc:"Replaces the list when present; [] clears it"`
		Enabled      *bool    `json:"enabled,omitempty"`
	}
}

type dlpDetectorGetInput struct {
	ID string `path:"id"`
}

type dlpDetectorDeleteInput struct {
	ID    string `path:"id"`
	Force bool   `query:"force" doc:"Take the detector out of every policy that names it, in the same transaction, instead of refusing"`
}

type dlpCustomDetectorOutput struct {
	Body dlp.CustomDetector
}

type dlpDetectorTestInput struct {
	Body struct {
		Pattern string   `json:"pattern" maxLength:"512"`
		Flags   string   `json:"flags,omitempty" enum:",i"`
		Samples []string `json:"samples" maxItems:"40" doc:"At most 1024 bytes each; 40, so an editor can try both of a detector's lists at once"`
	}
}

type dlpDetectorTestOutput struct {
	Body struct {
		Samples []dlp.SampleResult `json:"samples" nullable:"false"`
	}
}

func (d Deps) dlpDetectorRoutes(api huma.API, policies *dlp.Policies) {
	unconfigured := func() error { return huma.Error503ServiceUnavailable("data-loss prevention is not configured") }

	huma.Register(api, huma.Operation{OperationID: "dlp-detector-get", Method: http.MethodGet,
		Path: "/api/v1/dlp/detectors/{id}", Summary: "Read one of the organisation's own detectors",
		Tags: []string{"dlp"}, Security: sessionSecurity},
		func(ctx context.Context, in *dlpDetectorGetInput) (*dlpCustomDetectorOutput, error) {
			p, err := d.require(ctx, authz.ConnectorsRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if policies == nil {
				return nil, unconfigured()
			}
			got, err := policies.GetDetector(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, dlpErr(err)
			}
			return &dlpCustomDetectorOutput{Body: got}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "dlp-detector-create", Method: http.MethodPost,
		Path: "/api/v1/dlp/detectors", Summary: "Add a detector of the organisation's own",
		Description: "The pattern is compiled and every sample checked before anything is stored; a failing " +
			"sample is a 422 whose error location names it (body.mustMatch[2]).",
		Tags: []string{"dlp"}, Security: sessionSecurity, DefaultStatus: http.StatusCreated},
		func(ctx context.Context, in *dlpDetectorCreateInput) (*dlpCustomDetectorOutput, error) {
			p, err := d.requireFresh(ctx, authz.DLPManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if policies == nil {
				return nil, unconfigured()
			}
			b := in.Body
			got, err := policies.CreateDetector(ctx, p.OrgID, dlp.CustomDetector{Name: b.Name,
				Description: b.Description, Pattern: b.Pattern, Flags: b.Flags, MustMatch: b.MustMatch,
				MustNotMatch: b.MustNotMatch, Enabled: b.Enabled, CreatedBy: p.ID})
			if err != nil {
				d.adminFailed(ctx, "dlp.detector.create", "dlp_detector", "", err)
				return nil, dlpErr(err)
			}
			d.admin(ctx, "dlp.detector.create", "dlp_detector", got.ID, got.Name, audit.Created(got))
			return &dlpCustomDetectorOutput{Body: got}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "dlp-detector-update", Method: http.MethodPatch,
		Path: "/api/v1/dlp/detectors/{id}", Summary: "Change one of the organisation's own detectors",
		Description: "Fields left out keep their value. The detector is validated again as it would be stored, " +
			"samples included. expectedVersion is required; a mismatch is a 409 carrying the version stored now.",
		Tags: []string{"dlp"}, Security: sessionSecurity},
		func(ctx context.Context, in *dlpDetectorUpdateInput) (*dlpCustomDetectorOutput, error) {
			p, err := d.requireFresh(ctx, authz.DLPManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if policies == nil {
				return nil, unconfigured()
			}
			b := in.Body
			patch := dlp.DetectorPatch{Description: b.Description, Pattern: b.Pattern, Flags: b.Flags, Enabled: b.Enabled}
			if b.MustMatch != nil {
				patch.MustMatch = &b.MustMatch
			}
			if b.MustNotMatch != nil {
				patch.MustNotMatch = &b.MustNotMatch
			}
			if b.Name != nil {
				current, err := policies.GetDetector(ctx, p.OrgID, in.ID)
				if err != nil {
					return nil, dlpErr(err)
				}
				if *b.Name != current.Name {
					return nil, dlpErr(&dlp.DetectorError{Field: "name",
						Reason: "a detector's name cannot change: policies refer to it by name. Create a new detector instead"})
				}
			}
			before, got, err := policies.UpdateDetector(ctx, p.OrgID, in.ID, patch, b.ExpectedVersion, p.ID)
			if err != nil {
				d.adminFailed(ctx, "dlp.detector.update", "dlp_detector", in.ID, err)
				return nil, dlpErr(err)
			}
			d.admin(ctx, "dlp.detector.update", "dlp_detector", got.ID, got.Name, audit.Changes(before, got))
			return &dlpCustomDetectorOutput{Body: got}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "dlp-detector-delete", Method: http.MethodDelete,
		Path: "/api/v1/dlp/detectors/{id}", Summary: "Remove one of the organisation's own detectors",
		Description: "Refused with a 409 naming the policies that use the detector, unless force is set; then " +
			"it is taken out of those policies in the same transaction, and a policy left with no detector is " +
			"switched off rather than falling back to every built-in.",
		Tags: []string{"dlp"}, Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *dlpDetectorDeleteInput) (*struct{}, error) {
			p, err := d.requireFresh(ctx, authz.DLPManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if policies == nil {
				return nil, unconfigured()
			}
			before, changed, err := policies.DeleteDetector(ctx, p.OrgID, in.ID, in.Force, p.ID)
			if err != nil {
				d.adminFailed(ctx, "dlp.detector.delete", "dlp_detector", in.ID, err)
				return nil, dlpErr(err)
			}
			for _, c := range changed {
				d.admin(ctx, "dlp.policy.update", "dlp_policy", c.After.ID, c.After.Name, audit.Changes(c.Before, c.After))
			}
			d.admin(ctx, "dlp.detector.delete", "dlp_detector", before.ID, before.Name, audit.Deleted(before))
			return nil, nil //nolint:nilnil // huma's no-content shape
		})

	huma.Register(api, huma.Operation{OperationID: "dlp-detector-test", Method: http.MethodPost,
		Path: "/api/v1/dlp/detectors/test", Summary: "Try a pattern on samples before saving it",
		Description: "Applies the rules a save applies to the pattern and reports, per sample, whether it " +
			"matched and at which byte offsets. The samples are never quoted back.",
		Tags: []string{"dlp"}, Security: sessionSecurity},
		func(ctx context.Context, in *dlpDetectorTestInput) (*dlpDetectorTestOutput, error) {
			if _, err := d.require(ctx, authz.DLPManage, authz.Resource{}); err != nil {
				return nil, err
			}
			res, err := dlp.TestPattern(in.Body.Pattern, in.Body.Flags, in.Body.Samples)
			if err != nil {
				return nil, dlpErr(err)
			}
			out := &dlpDetectorTestOutput{}
			out.Body.Samples = res
			return out, nil
		})

	// A restore goes through the reader the tool-call path uses, like an
	// edit, so every replica hears of it the same way.
	huma.Register(api, huma.Operation{OperationID: "dlp-detectors-revisions-restore", Method: http.MethodPost,
		Path:    "/api/v1/dlp/detectors/{id}/revisions/{revision}/restore",
		Summary: "Put a custom data-loss detector back the way an earlier revision found it",
		Description: "Needs revisions:rollback and dlp:manage, and a browser session must have signed in within " +
			"the fresh-auth window. A deleted detector is recreated under its old id and name; the samples are " +
			"checked again.",
		Tags: []string{"dlp"}, Security: sessionSecurity},
		func(ctx context.Context, in *revisionGetInput) (*dlpCustomDetectorOutput, error) {
			p, snapshot, err := d.snapshotToRestore(ctx, dlpDetectorRevisions, in)
			if err != nil {
				return nil, err
			}
			if policies == nil {
				return nil, unconfigured()
			}
			var want dlp.CustomDetector
			if err := snapInto(snapshot, "", &want); err != nil {
				return nil, err
			}
			got, replaced, err := policies.RestoreDetector(ctx, p.OrgID, in.ID, want, p.ID)
			if err != nil {
				d.restoreFailed(ctx, dlpDetectorRevisions, in, err)
				return nil, dlpErr(err)
			}
			if replaced != nil {
				d.admin(ctx, "dlp.detector.update", "dlp_detector", got.ID, got.Name, audit.Changes(*replaced, got))
			} else {
				d.admin(ctx, "dlp.detector.create", "dlp_detector", got.ID, got.Name, audit.Created(got))
			}
			d.restored(ctx, dlpDetectorRevisions, in, got.Name)
			return &dlpCustomDetectorOutput{Body: got}, nil
		})
}
