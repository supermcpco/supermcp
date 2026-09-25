package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
)

// --- audit -----------------------------------------------------------------

// The stream is read-only over HTTP: nothing here edits or removes an
// event. Reading it is privileged in its own right, and taking a copy of
// it is privileged again, so the export asks for a separate permission and
// records that it happened.

// auditExportPage is how many rows the export reads per round trip. The
// export pages instead of holding one cursor open so a slow client cannot
// keep a transaction alive for the length of a download.
const auditExportPage = 500

// AuditFilter is what both the list and the export ask of the stream, so
// an operator can narrow a screen and then export exactly what they saw.
// The type is exported because huma finds query parameters by walking
// exported fields: an embedded field whose type is unexported is skipped,
// and every filter below would vanish from the API without a word.
type AuditFilter struct {
	Category string    `query:"category" doc:"auth, admin, tool, authz, secrets, system or governance"`
	Action   string    `query:"action" doc:"Exact action name, for example connector.created"`
	ActorID  string    `query:"actorId" doc:"Who acted"`
	TargetID string    `query:"targetId" doc:"What was acted on"`
	Outcome  string    `query:"outcome" enum:"success,failure,denied"`
	From     time.Time `query:"from" doc:"Only events at or after this RFC3339 time"`
	To       time.Time `query:"to" doc:"Only events at or before this RFC3339 time"`
}

type auditListInput struct {
	AuditFilter
	AfterSeq int64 `query:"afterSeq" doc:"Continue below this sequence number, taken from the previous page's nextSeq"`
	Limit    int   `query:"limit" default:"100" minimum:"1" maximum:"500"`
}

type auditExportInput struct {
	AuditFilter
}

type auditListOutput struct {
	Body struct {
		Events  []audit.Record `json:"events" nullable:"false"`
		NextSeq int64          `json:"nextSeq" doc:"Pass as afterSeq for the next page; zero at the end of the stream"`
	}
}

type auditVerifyOutput struct {
	Body *audit.VerifyResult
}

type auditPolicyOutput struct {
	Body struct {
		Mode string `json:"mode" enum:"none,metadata,masked,full"`
	}
}

type auditPolicyInput struct {
	Body struct {
		Mode string `json:"mode" enum:"none,metadata,masked,full" doc:"How much of a tool call's arguments and result the record keeps"`
	}
}

type auditRetentionOutput struct {
	Body struct {
		Days        int  `json:"days" doc:"Events older than this lose their content; the fact that they happened stays in the chain"`
		Configured  bool `json:"configured" doc:"False while the workspace is on the default"`
		DefaultDays int  `json:"defaultDays"`
		MinDays     int  `json:"minDays"`
		MaxDays     int  `json:"maxDays"`
	}
}

type auditRetentionInput struct {
	Body struct {
		Days int `json:"days" doc:"How many days events keep their content; between minDays and maxDays"`
	}
}

// query turns the request filters into a read, scoped to one organisation.
// A zero time means the caller did not ask for that bound.
func (f AuditFilter) query(orgID string) audit.Query {
	q := audit.Query{OrgID: orgID, Category: f.Category, Action: f.Action,
		ActorID: f.ActorID, TargetID: f.TargetID, Outcome: f.Outcome}
	if !f.From.IsZero() {
		from := f.From
		q.From = &from
	}
	if !f.To.IsZero() {
		to := f.To
		q.To = &to
	}
	return q
}

func (d Deps) auditRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "audit-list", Method: http.MethodGet, Path: "/api/v1/audit",
		Summary: "List audit events", Tags: []string{"audit"}, Security: sessionSecurity},
		func(ctx context.Context, in *auditListInput) (*auditListOutput, error) {
			p, err := d.require(ctx, authz.AuditRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if d.AuditReader == nil {
				return nil, huma.Error503ServiceUnavailable("the audit stream is not configured")
			}
			q := in.query(p.OrgID)
			q.AfterSeq, q.Limit = in.AfterSeq, in.Limit
			events, err := d.AuditReader.List(ctx, q)
			if err != nil {
				return nil, err
			}
			out := &auditListOutput{}
			out.Body.Events = events
			// Only a full page can have anything behind it; a short one is
			// the end, and saying so saves the client a round trip.
			if q.Limit > 0 && len(events) == q.Limit {
				out.Body.NextSeq = events[len(events)-1].Seq
			}
			return out, nil
		})

	// Verification covers the whole instance chain, not one tenant: events
	// from every organisation share a single sequence, so checking an
	// organisation's range necessarily walks the rows other tenants wrote
	// in between. That is what makes the verdict worth anything — a gap is
	// a gap whoever left it — and only the verdict crosses back, never
	// another tenant's event.
	huma.Register(api, huma.Operation{OperationID: "audit-verify", Method: http.MethodGet, Path: "/api/v1/audit/verify",
		Summary: "Check that the audit chain is intact", Tags: []string{"audit"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*auditVerifyOutput, error) {
			p, err := d.require(ctx, authz.AuditRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if d.AuditReader == nil {
				return nil, huma.Error503ServiceUnavailable("the audit stream is not configured")
			}
			first, last, err := d.AuditReader.SeqRange(ctx, p.OrgID)
			if err != nil {
				return nil, err
			}
			if first == 0 && last == 0 {
				// An organisation with no events has nothing to check, and
				// an unbounded range would verify the whole instance.
				return &auditVerifyOutput{Body: &audit.VerifyResult{Valid: true}}, nil
			}
			res, err := d.AuditReader.Verify(ctx, first, last)
			if err != nil {
				return nil, err
			}
			return &auditVerifyOutput{Body: res}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "audit-export", Method: http.MethodGet, Path: "/api/v1/audit/export",
		Summary: "Export audit events as newline-delimited JSON", Tags: []string{"audit"}, Security: sessionSecurity,
		Responses: map[string]*huma.Response{
			"200": {Description: "One event per line, newest first",
				Content: map[string]*huma.MediaType{"application/x-ndjson": {}}},
		}},
		func(ctx context.Context, in *auditExportInput) (*huma.StreamResponse, error) {
			p, err := d.require(ctx, authz.AuditExport, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if d.AuditReader == nil {
				return nil, huma.Error503ServiceUnavailable("the audit stream is not configured")
			}
			q := in.query(p.OrgID)
			q.Limit = auditExportPage
			filename := "audit-" + time.Now().UTC().Format("20060102T150405Z") + ".ndjson"

			// A copy of the record leaving the instance is itself an event,
			// and it is recorded before the first byte goes out, because an
			// export that fails half way still happened.
			d.emit(ctx, audit.Event{Category: audit.CategoryAdmin, Action: "audit.exported", Outcome: audit.Success,
				TargetKind: "organization", TargetID: p.OrgID,
				Meta: map[string]any{"format": "ndjson", "category": in.Category, "action": in.Action}})

			log, orgID := d.Log, p.OrgID
			reader := d.AuditReader
			// The stream outlives the handler's own context; what bounds
			// it is the response context huma hands the body.
			return &huma.StreamResponse{Body: func(hc huma.Context) { //nolint:contextcheck // the stream has its own context
				hc.SetHeader("Content-Type", "application/x-ndjson")
				hc.SetHeader("Content-Disposition", `attachment; filename="`+filename+`"`)
				enc := json.NewEncoder(hc.BodyWriter())
				for {
					batch, err := reader.List(hc.Context(), q)
					if err != nil {
						log.Error("audit export stopped early", "org", orgID, "after_seq", q.AfterSeq, "err", err)
						return
					}
					for i := range batch {
						if err := enc.Encode(batch[i]); err != nil {
							return
						}
					}
					if len(batch) < q.Limit {
						return
					}
					q.AfterSeq = batch[len(batch)-1].Seq
				}
			}}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "audit-get-policy", Method: http.MethodGet, Path: "/api/v1/audit/policy",
		Summary: "Read how much of a tool call's payload is recorded", Tags: []string{"audit"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*auditPolicyOutput, error) {
			p, err := d.require(ctx, authz.AuditRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if d.AuditPolicies == nil {
				return nil, huma.Error503ServiceUnavailable("the audit stream is not configured")
			}
			out := &auditPolicyOutput{}
			out.Body.Mode = string(d.AuditPolicies.Mode(ctx, p.OrgID))
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "audit-set-policy", Method: http.MethodPut, Path: "/api/v1/audit/policy",
		Summary: "Set how much of a tool call's payload is recorded", Tags: []string{"audit"}, Security: sessionSecurity},
		func(ctx context.Context, in *auditPolicyInput) (*auditPolicyOutput, error) {
			p, err := d.requireFresh(ctx, authz.AuditPolicy, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if d.AuditPolicies == nil {
				return nil, huma.Error503ServiceUnavailable("the audit stream is not configured")
			}
			before := d.AuditPolicies.Mode(ctx, p.OrgID)
			mode := audit.PayloadMode(in.Body.Mode)
			if err := d.AuditPolicies.SetMode(ctx, p.OrgID, mode); err != nil {
				d.adminFailed(ctx, "audit.policy.set", "organization", p.OrgID, err)
				return nil, humaErr(err)
			}
			d.admin(ctx, "audit.policy.set", "organization", p.OrgID, "",
				audit.Changes(map[string]any{"payloadMode": string(before)}, map[string]any{"payloadMode": string(mode)}))
			out := &auditPolicyOutput{}
			out.Body.Mode = string(mode)
			return out, nil
		})

	// Retention is a policy decision like the payload one: shortening it
	// removes content from the record, so it takes the same permission,
	// not the auditor's export-and-hold one.
	huma.Register(api, huma.Operation{OperationID: "audit-get-retention", Method: http.MethodGet, Path: "/api/v1/audit/retention",
		Summary: "Read how long the workspace's audit events keep their content", Tags: []string{"audit"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*auditRetentionOutput, error) {
			p, err := d.require(ctx, authz.AuditRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if d.AuditRetention == nil {
				return nil, huma.Error503ServiceUnavailable("the audit stream is not configured")
			}
			return d.retentionOutput(ctx, p.OrgID)
		})

	huma.Register(api, huma.Operation{OperationID: "audit-set-retention", Method: http.MethodPut, Path: "/api/v1/audit/retention",
		Summary: "Set how long the workspace's audit events keep their content", Tags: []string{"audit"}, Security: sessionSecurity},
		func(ctx context.Context, in *auditRetentionInput) (*auditRetentionOutput, error) {
			p, err := d.requireFresh(ctx, authz.AuditPolicy, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if d.AuditRetention == nil {
				return nil, huma.Error503ServiceUnavailable("the audit stream is not configured")
			}
			before, err := d.AuditRetention.Setting(ctx, p.OrgID)
			if err != nil {
				return nil, err
			}
			if err := d.AuditRetention.SetDays(ctx, p.OrgID, in.Body.Days); err != nil {
				d.adminFailed(ctx, "audit.retention.set", "organization", p.OrgID, err)
				var outOfRange *audit.RetentionRangeError
				if errors.As(err, &outOfRange) {
					return nil, huma.Error422UnprocessableEntity(outOfRange.Error())
				}
				return nil, err
			}
			d.admin(ctx, "audit.retention.set", "organization", p.OrgID, "",
				audit.Changes(map[string]any{"retentionDays": before.Days}, map[string]any{"retentionDays": in.Body.Days}))
			return d.retentionOutput(ctx, p.OrgID)
		})
}

// retentionOutput reads the workspace's window alongside the bounds, so a
// client never has to hard-code them. It does not say when rows are
// finally deleted: that is the longest window any workspace keeps, and
// one workspace has no business learning another's choice.
func (d Deps) retentionOutput(ctx context.Context, orgID string) (*auditRetentionOutput, error) {
	setting, err := d.AuditRetention.Setting(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := &auditRetentionOutput{}
	out.Body.Days = setting.Days
	out.Body.Configured = setting.Configured
	out.Body.DefaultDays = audit.DefaultRetentionDays
	out.Body.MinDays = audit.MinRetentionDays
	out.Body.MaxDays = audit.MaxRetentionDays
	return out, nil
}
