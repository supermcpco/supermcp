package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/invoke"
	"github.com/supermcpco/supermcp/internal/tool"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// A tool's definition travels as a JSON string rather than an object: the
// schema cannot be described (it holds free-form JSON Schema and mapping
// nodes), and a string keeps the author's key order through the round
// trip, which an object decoded into a map would not.

// toolDTO is a tool in a list.
type toolDTO struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Enabled     bool               `json:"enabled"`
	Source      string             `json:"source" enum:"catalog,import,custom" doc:"Where the tool came from; only custom tools can be deleted"`
	Edited      bool               `json:"edited" doc:"Someone changed the definition by hand; a catalog re-sync leaves it alone"`
	Version     int64              `json:"version" doc:"Send back as expectedVersion when updating"`
	Annotations toolAnnotationsDTO `json:"annotations" doc:"The hints clients see: derived from the operation, then explicit overrides applied"`
}

// toolAnnotationsDTO is a set of resolved MCP tool hints.
type toolAnnotationsDTO struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    bool   `json:"readOnlyHint"`
	DestructiveHint bool   `json:"destructiveHint"`
	IdempotentHint  bool   `json:"idempotentHint"`
	OpenWorldHint   bool   `json:"openWorldHint"`
}

// toolDetailDTO is one tool with its full definition. It repeats the
// toolDTO fields instead of embedding toolDTO: huma skips unexported
// embedded structs when it builds the schema.
type toolDetailDTO struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Enabled     bool               `json:"enabled"`
	Source      string             `json:"source" enum:"catalog,import,custom" doc:"Where the tool came from; only custom tools can be deleted"`
	Edited      bool               `json:"edited" doc:"Someone changed the definition by hand; a catalog re-sync leaves it alone"`
	Version     int64              `json:"version" doc:"Send back as expectedVersion when updating"`
	Annotations toolAnnotationsDTO `json:"annotations" doc:"The hints clients see: derived from the operation, then explicit overrides applied"`
	ConnectorID string             `json:"connectorId"`
	Transport   string             `json:"transport" enum:"http,graphql,database,soap,mcp" doc:"The connector's transport; decides which operation fields apply"`
	Definition  string             `json:"definition" doc:"The tool definition as a JSON document, in its stored key order"`
	// InferredAnnotations is what the operation alone implies, before the
	// definition's explicit hints; the editor shows it as the "auto" value.
	InferredAnnotations toolAnnotationsDTO `json:"inferredAnnotations" doc:"The hints derived from the operation alone, before explicit overrides"`
	EditedAt            *time.Time         `json:"editedAt,omitempty"`
	EditedBy            string             `json:"editedBy,omitempty"`
	EditedByName        string             `json:"editedByName,omitempty" doc:"The editor's name, or address when they have no name"`
	CreatedAt           time.Time          `json:"createdAt"`
	UpdatedAt           time.Time          `json:"updatedAt"`
}

// toolIssueDTO is one validation finding about a definition.
type toolIssueDTO struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity" enum:"error,warning"`
	Message  string `json:"message"`
	Field    string `json:"field,omitempty" doc:"Dotted path inside the definition, e.g. operation.path; empty for the whole tool"`
}

// toolWriteBody is a tool create or update.
type toolWriteBody struct {
	Definition            string `json:"definition" minLength:"2" doc:"The tool definition as a JSON document"`
	Enabled               *bool  `json:"enabled,omitempty" doc:"Leave out to keep the current value; new tools default to enabled"`
	ExpectedVersion       int64  `json:"expectedVersion,omitempty" doc:"Required on update: the version that was read. A mismatch is a 409"`
	AcknowledgeReferences bool   `json:"acknowledgeReferences,omitempty" doc:"Rename even though approval policies match the tool by its current name"`
}

// toolWriteResult is what a create or update returns.
type toolWriteResult struct {
	Tool     toolDetailDTO  `json:"tool"`
	Warnings []toolIssueDTO `json:"warnings" nullable:"false"`
}

// toolDraftBody is an unsaved definition to check and preview.
type toolDraftBody struct {
	Definition string         `json:"definition" doc:"The draft tool definition as a JSON document"`
	ToolID     string         `json:"toolId,omitempty" doc:"The tool being edited, if any; leave out for a new tool"`
	Arguments  map[string]any `json:"arguments,omitempty" doc:"What the model would send"`
}

// toolDraftResult is the check and preview of a draft.
type toolDraftResult struct {
	Issues []toolIssueDTO `json:"issues" nullable:"false"`
	// Annotations and InferredAnnotations are nil when the draft does not
	// parse.
	Annotations         *toolAnnotationsDTO `json:"annotations,omitempty" doc:"The hints the draft would resolve to"`
	InferredAnnotations *toolAnnotationsDTO `json:"inferredAnnotations,omitempty" doc:"The hints the draft's operation implies before explicit overrides"`
	// Preview is nil when the draft has errors, the transport cannot be
	// previewed, or rendering failed (then PreviewError says why).
	Preview      *engine.Preview `json:"preview,omitempty"`
	PreviewError string          `json:"previewError,omitempty" doc:"Why the request could not be rendered"`
}

// toolReferencesDTO is what refers to a tool.
type toolReferencesDTO struct {
	ApprovalPolicies []toolPolicyRefDTO `json:"approvalPolicies" nullable:"false"`
	AccessRules      int                `json:"accessRules" doc:"Role allow/deny rules naming the tool; removed with it"`
	DLPPolicies      int                `json:"dlpPolicies" doc:"DLP policies scoped to the tool; removed with it"`
}

// toolPolicyRefDTO is one approval policy that refers to a tool.
type toolPolicyRefDTO struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Match   string `json:"match" enum:"name,scope" doc:"name: matches the tool by name and stops matching on rename or delete; scope: scoped to the tool"`
}

// --- inputs and outputs ------------------------------------------------------

type toolIDInput struct {
	ID string `path:"id" doc:"The tool"`
}

type toolDetailOutput struct{ Body toolDetailDTO }

type toolCreateInput struct {
	ID   string `path:"id" doc:"The connector"`
	Body toolWriteBody
}

type toolUpdateInput struct {
	ID   string `path:"id" doc:"The tool"`
	Body toolWriteBody
}

type toolWriteOutput struct{ Body toolWriteResult }

type toolDeleteInput struct {
	ID                    string `path:"id" doc:"The tool"`
	AcknowledgeReferences bool   `query:"acknowledgeReferences" doc:"Delete even though approval policies match the tool by name"`
}

type toolReferencesOutput struct{ Body toolReferencesDTO }

type toolDraftInput struct {
	ID   string `path:"id" doc:"The connector"`
	Body toolDraftBody
}

type toolDraftOutput struct{ Body toolDraftResult }

// --- routes --------------------------------------------------------------------

// Every tool route finds the tool's connector before it checks a
// permission, so a binding scoped to the connector covers the tool. When
// the tool cannot be found the check runs against the tool alone first: a
// caller without access gets the same 403 whether or not the tool exists.
//
// Editing a tool is tools:update. Anything that changes what a call does
// (and creating or deleting a tool, which does too) also needs
// connectors:update, because it is the connector's credential the call
// carries. Taking the destructive hint off a tool whose operation implies
// it also needs tools:invoke:destructive: otherwise an editor could turn a
// destructive tool into one anybody with tools:invoke may call.

func (d Deps) toolRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "tools-get", Method: http.MethodGet, Path: "/api/v1/tools/{id}",
		Summary: "Get a tool with its definition", Tags: []string{"tools"}, Security: sessionSecurity},
		func(ctx context.Context, in *toolIDInput) (*toolDetailOutput, error) {
			p, t, err := d.requireTool(ctx, authz.ToolsRead, in.ID)
			if err != nil {
				return nil, err
			}
			c, err := d.Connectors.Get(ctx, p.OrgID, t.ConnectorID)
			if err != nil {
				return nil, humaErr(err)
			}
			dto, err := d.toolDetail(ctx, p.OrgID, t, c)
			if err != nil {
				return nil, err
			}
			return &toolDetailOutput{Body: dto}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "tools-create", Method: http.MethodPost, Path: "/api/v1/connectors/{id}/tools",
		Summary: "Add a custom tool to a connector", Tags: []string{"tools"}, Security: sessionSecurity,
		DefaultStatus: http.StatusCreated},
		func(ctx context.Context, in *toolCreateInput) (*toolWriteOutput, error) {
			r := authz.Resource{ConnectorID: in.ID}
			p, err := d.require(ctx, authz.ToolsUpdate, r)
			if err != nil {
				return nil, err
			}
			if _, err := d.require(ctx, authz.ConnectorsUpdate, r); err != nil {
				return nil, err
			}
			def, err := parseDefinition(in.Body.Definition)
			if err != nil {
				return nil, err
			}
			c, err := d.Connectors.Get(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, humaErr(err)
			}
			declassified := tool.Declassifies(nil, def, c.Transport.Type, c.ReadOnly)
			if declassified {
				if _, err := d.require(ctx, authz.ToolsInvokeDestr, authz.Resource{ConnectorID: in.ID, Destructive: true}); err != nil {
					return nil, err
				}
			}
			t, warnings, err := d.Connectors.CreateTool(ctx, p.OrgID, in.ID, connector.ToolInput{
				Definition: def, Enabled: in.Body.Enabled, ActorID: p.ID,
			})
			if err != nil {
				d.adminFailed(ctx, "tool.create", "tool", "", err)
				return nil, humaErr(err)
			}
			d.toolChanged(ctx, "tool.create", t, audit.Created(toolAudit(t)), declassified)
			return d.toolWritten(ctx, p.OrgID, t, c, warnings)
		})

	huma.Register(api, huma.Operation{OperationID: "tools-update", Method: http.MethodPut, Path: "/api/v1/tools/{id}",
		Summary: "Replace a tool's definition", Tags: []string{"tools"}, Security: sessionSecurity},
		func(ctx context.Context, in *toolUpdateInput) (*toolWriteOutput, error) {
			p, before, err := d.requireTool(ctx, authz.ToolsUpdate, in.ID)
			if err != nil {
				return nil, err
			}
			if in.Body.ExpectedVersion == 0 {
				return nil, huma.Error422UnprocessableEntity("expectedVersion is required: send the version that was read",
					&huma.ErrorDetail{Location: "body.expectedVersion", Message: "required"})
			}
			// The permission checks below are decided against the version
			// just read. The service refuses the write unless the stored
			// version still equals expectedVersion, so insisting that they
			// agree here ties the decision to the row that gets replaced.
			if err := connector.CheckVersion("tool", in.Body.ExpectedVersion, before.Version); err != nil {
				return nil, humaErr(err)
			}
			def, err := parseDefinition(in.Body.Definition)
			if err != nil {
				return nil, err
			}
			u, err := d.updateTool(ctx, p, before, connector.ToolInput{
				Definition: def, Enabled: in.Body.Enabled, ExpectedVersion: in.Body.ExpectedVersion,
				AcknowledgeReferences: in.Body.AcknowledgeReferences, ActorID: p.ID,
			})
			if err != nil {
				return nil, err
			}
			d.toolChanged(ctx, "tool.update", u.tool, audit.Changes(toolAudit(before), toolAudit(u.tool)), u.declassified)
			return d.toolWritten(ctx, p.OrgID, u.tool, u.conn, u.warnings)
		})

	huma.Register(api, huma.Operation{OperationID: "tools-delete", Method: http.MethodDelete, Path: "/api/v1/tools/{id}",
		Summary: "Delete a custom tool", Tags: []string{"tools"}, Security: sessionSecurity,
		DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *toolDeleteInput) (*struct{}, error) {
			p, before, err := d.requireTool(ctx, authz.ToolsUpdate, in.ID)
			if err != nil {
				return nil, err
			}
			if _, err := d.require(ctx, authz.ConnectorsUpdate, toolResource(before)); err != nil {
				return nil, err
			}
			if err := d.Connectors.DeleteTool(ctx, p.OrgID, in.ID, in.AcknowledgeReferences, p.ID); err != nil {
				d.adminFailed(ctx, "tool.delete", "tool", in.ID, err)
				return nil, d.toolWriteErr(ctx, p.OrgID, in.ID, false, err)
			}
			d.toolChanged(ctx, "tool.delete", before, audit.Deleted(toolAudit(before)), false)
			return &struct{}{}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "tools-references", Method: http.MethodGet, Path: "/api/v1/tools/{id}/references",
		Summary: "List what refers to a tool", Tags: []string{"tools"}, Security: sessionSecurity},
		func(ctx context.Context, in *toolIDInput) (*toolReferencesOutput, error) {
			p, _, err := d.requireTool(ctx, authz.ToolsRead, in.ID)
			if err != nil {
				return nil, err
			}
			refs, err := d.Connectors.ToolReferences(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, humaErr(err)
			}
			out := toolReferencesDTO{ApprovalPolicies: make([]toolPolicyRefDTO, 0, len(refs.ApprovalPolicies)),
				AccessRules: refs.AccessRules, DLPPolicies: refs.DLPPolicies}
			for _, r := range refs.ApprovalPolicies {
				out.ApprovalPolicies = append(out.ApprovalPolicies, toolPolicyRefDTO{ID: r.ID, Name: r.Name, Enabled: r.Enabled, Match: r.Match})
			}
			return &toolReferencesOutput{Body: out}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "tools-draft-dry-run", Method: http.MethodPost, Path: "/api/v1/connectors/{id}/tools/dry-run",
		Summary: "Check an unsaved tool definition and render the request it would send", Tags: []string{"tools"},
		Security: sessionSecurity},
		func(ctx context.Context, in *toolDraftInput) (*toolDraftOutput, error) {
			return d.draftDryRun(ctx, in)
		})
}

// draftDryRun checks a draft and, when it has no errors, renders the
// request it would send. Problems with the draft are the answer, not a
// failure: they come back with a 200 so the editor can show them as the
// author types.
func (d Deps) draftDryRun(ctx context.Context, in *toolDraftInput) (*toolDraftOutput, error) {
	r := authz.Resource{ConnectorID: in.ID, ToolID: in.Body.ToolID}
	p, err := d.require(ctx, authz.ToolsUpdate, r)
	if err != nil {
		return nil, err
	}
	// A preview renders the connector's credential into the request, so it
	// asks for the permission to make the call, as the saved-tool preview
	// does.
	if _, err := d.require(ctx, authz.ToolsInvoke, r); err != nil {
		return nil, err
	}
	// A tool-scoped binding must not reach another connector's credential
	// by naming its own tool next to that connector.
	if in.Body.ToolID != "" {
		t, err := d.Connectors.GetTool(ctx, p.OrgID, in.Body.ToolID)
		if err != nil || t.ConnectorID != in.ID {
			return nil, huma.Error404NotFound("no such tool on this connector")
		}
	}
	c, err := d.Connectors.Get(ctx, p.OrgID, in.ID)
	if err != nil {
		return nil, humaErr(err)
	}

	out := &toolDraftOutput{Body: toolDraftResult{Issues: []toolIssueDTO{}}}
	def, perr := connector.ParseToolJSON([]byte(in.Body.Definition))
	if perr != nil {
		out.Body.Issues = append(out.Body.Issues, toolIssueDTO{Rule: "json", Severity: string(adapter.SeverityError),
			Message: "the definition is not valid JSON: " + perr.Error()})
		return out, nil
	}
	resolved := annotationsToDTO(tool.Derive(def, c.Transport.Type, c.ReadOnly))
	inferred := annotationsToDTO(tool.DeriveOperation(def, c.Transport.Type, c.ReadOnly))
	out.Body.Annotations, out.Body.InferredAnnotations = &resolved, &inferred

	issues, err := d.Connectors.CheckTool(ctx, p.OrgID, in.ID, in.Body.ToolID, def)
	if err != nil {
		return nil, humaErr(err)
	}
	out.Body.Issues = issuesToDTO(issues)
	if hasError(issues) || d.Executor == nil {
		return out, nil
	}
	preview, err := d.Executor.DryRun(ctx, invoke.Call{
		Principal: p, Connector: c, Args: in.Body.Arguments, Draft: true,
		Tool: &connector.Tool{ID: in.Body.ToolID, ConnectorID: in.ID, Name: def.Name, Definition: def},
	})
	switch {
	case errors.Is(err, engine.ErrUnsupported):
		out.Body.PreviewError = "a preview is not available for " + string(c.Transport.Type) + " tools"
	case err != nil:
		msg, ok := renderRefusal(err)
		if !ok {
			return nil, humaErr(err)
		}
		out.Body.PreviewError = msg
	default:
		out.Body.Preview = preview
	}
	return out, nil
}

// toolUpdate is the outcome of updateTool.
type toolUpdate struct {
	tool     *connector.Tool
	conn     *connector.Connector // the tool's connector, for the reply
	warnings []adapter.Issue
	// declassified: the edit took the destructive hint off an operation
	// that implies it.
	declassified bool
}

// updateTool checks the escalations an edit needs and applies it. The
// PUT handler and a revision restore both go through it, so a restore
// cannot do what an edit may not. Failures are recorded and already
// mapped to HTTP errors.
func (d Deps) updateTool(ctx context.Context, p *authz.Principal, before *connector.Tool, in connector.ToolInput) (*toolUpdate, error) {
	c, err := d.Connectors.Get(ctx, p.OrgID, before.ConnectorID)
	if err != nil {
		return nil, humaErr(err)
	}
	r := toolResource(before)
	if connector.BehaviourChanged(before.Definition, in.Definition) {
		if _, err := d.require(ctx, authz.ConnectorsUpdate, r); err != nil {
			return nil, err
		}
	}
	declassified := tool.Declassifies(before.Definition, in.Definition, c.Transport.Type, c.ReadOnly)
	if declassified {
		r.Destructive = true
		if _, err := d.require(ctx, authz.ToolsInvokeDestr, r); err != nil {
			return nil, err
		}
	}
	t, warnings, err := d.Connectors.UpdateTool(ctx, p.OrgID, before.ID, in)
	if err != nil {
		d.adminFailed(ctx, "tool.update", "tool", before.ID, err)
		return nil, d.toolWriteErr(ctx, p.OrgID, before.ID, true, err)
	}
	return &toolUpdate{tool: t, conn: c, warnings: warnings, declassified: declassified}, nil
}

// requireTool loads a tool and checks perm against it and its connector.
func (d Deps) requireTool(ctx context.Context, perm authz.Permission, toolID string) (*authz.Principal, *connector.Tool, error) {
	p, ok := authz.From(ctx)
	if !ok || p.OrgID == "" || d.Connectors == nil {
		// require produces the right refusal for a missing session or
		// organisation.
		if _, err := d.require(ctx, perm, authz.Resource{ToolID: toolID}); err != nil {
			return nil, nil, err
		}
		return nil, nil, huma.Error503ServiceUnavailable("connectors are not configured")
	}
	t, err := d.Connectors.GetTool(ctx, p.OrgID, toolID)
	if err != nil {
		if _, rerr := d.require(ctx, perm, authz.Resource{ToolID: toolID}); rerr != nil {
			return nil, nil, rerr
		}
		return nil, nil, humaErr(err)
	}
	if _, err := d.require(ctx, perm, toolResource(t)); err != nil {
		return nil, nil, err
	}
	return p, t, nil
}

// toolWritten is the reply to a create or update.
func (d Deps) toolWritten(ctx context.Context, orgID string, t *connector.Tool, c *connector.Connector, warnings []adapter.Issue) (*toolWriteOutput, error) {
	dto, err := d.toolDetail(ctx, orgID, t, c)
	if err != nil {
		return nil, err
	}
	return &toolWriteOutput{Body: toolWriteResult{Tool: dto, Warnings: issuesToDTO(warnings)}}, nil
}

// toolChanged records a tool write. meta.declassified marks an edit that
// took the destructive hint off an operation that implies it, which is
// the change an auditor looks for first.
func (d Deps) toolChanged(ctx context.Context, action string, t *connector.Tool, diff *audit.Diff, declassified bool) {
	e := audit.Event{Category: audit.CategoryAdmin, Action: action, Outcome: audit.Success,
		TargetKind: "tool", TargetID: t.ID, TargetDisplay: t.Name, Diff: diff}
	if declassified {
		e.Meta = map[string]any{"declassified": true}
	}
	d.emit(ctx, e)
}

// --- helpers -------------------------------------------------------------------

// toolResource is what a permission on an existing tool is checked
// against: the tool and its connector, so both tool- and connector-scoped
// bindings apply.
func toolResource(t *connector.Tool) authz.Resource {
	return authz.Resource{ConnectorID: t.ConnectorID, ToolID: t.ID}
}

// parseDefinition reads a definition from a request body.
func parseDefinition(s string) (*adapter.Tool, error) {
	def, err := connector.ParseToolJSON([]byte(s))
	if err != nil {
		return nil, huma.Error422UnprocessableEntity("the definition is not valid JSON",
			&huma.ErrorDetail{Location: "body.definition", Message: err.Error()})
	}
	return def, nil
}

// toolAuditView is what the audit diff records of a tool. The definition
// goes in whole, as an object, so a reader sees the fields that changed.
type toolAuditView struct {
	Name       string          `json:"name"`
	Enabled    bool            `json:"enabled"`
	Source     string          `json:"source,omitempty"`
	Definition json.RawMessage `json:"definition,omitempty"`
}

func toolAudit(t *connector.Tool) toolAuditView {
	v := toolAuditView{Name: t.Name, Enabled: t.Enabled, Source: t.Source}
	if t.Definition != nil {
		if raw, err := connector.DefinitionJSON(t.Definition); err == nil {
			v.Definition = raw
		}
	}
	return v
}

// toolToDTO is the list shape of a tool. c is the tool's connector: the
// derived hints depend on its transport and whether it is read-only.
func toolToDTO(t *connector.Tool, c *connector.Connector) toolDTO {
	return toolDTO{ID: t.ID, Name: t.Name, Description: t.Definition.Description, Enabled: t.Enabled,
		Source: t.Source, Edited: t.EditedAt != nil, Version: t.Version,
		Annotations: annotationsToDTO(tool.Derive(t.Definition, c.Transport.Type, c.ReadOnly))}
}

// toolDetail is one tool with its definition, and who edited it by name.
func (d Deps) toolDetail(ctx context.Context, orgID string, t *connector.Tool, c *connector.Connector) (toolDetailDTO, error) {
	dto, err := toolDetailToDTO(t, c)
	if err != nil {
		return dto, err
	}
	dto.EditedByName = d.editorName(ctx, orgID, t.EditedBy)
	return dto, nil
}

// toolDetailToDTO is one tool with its definition.
func toolDetailToDTO(t *connector.Tool, c *connector.Connector) (toolDetailDTO, error) {
	raw, err := connector.DefinitionJSON(t.Definition)
	if err != nil {
		return toolDetailDTO{}, fmt.Errorf("encode tool %s definition: %w", t.ID, err)
	}
	return toolDetailDTO{
		ID: t.ID, Name: t.Name, Description: t.Definition.Description, Enabled: t.Enabled,
		Source: t.Source, Edited: t.EditedAt != nil, Version: t.Version,
		Annotations:         annotationsToDTO(tool.Derive(t.Definition, c.Transport.Type, c.ReadOnly)),
		InferredAnnotations: annotationsToDTO(tool.DeriveOperation(t.Definition, c.Transport.Type, c.ReadOnly)),
		ConnectorID:         t.ConnectorID, Transport: string(c.Transport.Type), Definition: string(raw),
		EditedAt: t.EditedAt, EditedBy: t.EditedBy, CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}, nil
}

func annotationsToDTO(a tool.Annotations) toolAnnotationsDTO {
	return toolAnnotationsDTO{Title: a.Title, ReadOnlyHint: a.ReadOnlyHint, DestructiveHint: a.DestructiveHint,
		IdempotentHint: a.IdempotentHint, OpenWorldHint: a.OpenWorldHint}
}

func issuesToDTO(issues []adapter.Issue) []toolIssueDTO {
	out := make([]toolIssueDTO, 0, len(issues))
	for _, i := range issues {
		out = append(out, toolIssueDTO{Rule: i.Rule, Severity: string(i.Severity), Message: i.Message, Field: i.Field})
	}
	return out
}

func hasError(issues []adapter.Issue) bool {
	for _, i := range issues {
		if i.Severity == adapter.SeverityError {
			return true
		}
	}
	return false
}

// Machine codes for the tool 409s. A client matches on the error
// detail's value, never on the message, which is written for people.
const (
	conflictVersion    = "version_conflict"
	conflictNameTaken  = "name_taken"
	conflictDeletable  = "not_deletable"
	conflictReferences = "references_unacknowledged"
	// conflictResyncStale: the connector or the catalog changed since the
	// re-sync was reviewed.
	conflictResyncStale = "resync_stale"
)

// toolNameRule is the issue rule for a name another tool on the
// connector already has.
const toolNameRule = "tool-name-unique"

// toolNameConstraint is the unique (connector_id, name) key on tools.
const toolNameConstraint = "tools_connector_id_name_key"

// toolConflict maps the tool write conflicts to a 409 carrying a machine
// code, or returns nil when err is not one. A definition whose only error
// is a taken name is a conflict too: nothing is wrong with it except what
// else exists.
func toolConflict(err error) error {
	code, loc := "", "body"
	var invalid *connector.InvalidToolError
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, connector.ErrVersionConflict):
		return versionConflict(err)
	case errors.Is(err, connector.ErrToolNameTaken),
		errors.As(err, &invalid) && onlyNameTaken(invalid.Issues),
		errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == toolNameConstraint:
		return huma.Error409Conflict(connector.ErrToolNameTaken.Error(),
			&huma.ErrorDetail{Location: "body.definition", Message: connector.ErrToolNameTaken.Error(), Value: conflictNameTaken})
	case errors.Is(err, connector.ErrToolNotDeletable):
		code = conflictDeletable
	case errors.Is(err, connector.ErrReferencesNotAcknowledged):
		code, loc = conflictReferences, "body.acknowledgeReferences"
	default:
		return nil
	}
	return huma.Error409Conflict(err.Error(), &huma.ErrorDetail{Location: loc, Message: err.Error(), Value: code})
}

// versionConflict is the 409 for a tool, connector or server write made
// against a version somebody has since replaced. Beside the code it
// carries the version stored now, at location "version", so a client can
// tell what it would be reloading to.
func versionConflict(err error) error {
	details := []error{&huma.ErrorDetail{Location: "body.expectedVersion", Message: err.Error(), Value: conflictVersion}}
	var stale *connector.VersionConflictError
	if errors.As(err, &stale) {
		details = append(details, &huma.ErrorDetail{Location: "version", Message: "the version stored now", Value: stale.Current})
	}
	return huma.Error409Conflict(err.Error(), details...)
}

func onlyNameTaken(issues []adapter.Issue) bool {
	named := false
	for _, i := range issues {
		if i.Severity != adapter.SeverityError {
			continue
		}
		if i.Rule != toolNameRule {
			return false
		}
		named = true
	}
	return named
}

// toolWriteErr maps a tool write failure. A refusal over approval
// policies also lists them, one detail each (message the policy name,
// value its id), so the client can ask for confirmation without a second
// request. A rename is refused only over policies that match the name; a
// delete over every policy that refers to the tool (byNameOnly false).
func (d Deps) toolWriteErr(ctx context.Context, orgID, toolID string, byNameOnly bool, err error) error {
	if !errors.Is(err, connector.ErrReferencesNotAcknowledged) || toolID == "" {
		return humaErr(err)
	}
	details := []error{&huma.ErrorDetail{Location: "body.acknowledgeReferences", Message: err.Error(), Value: conflictReferences}}
	if refs, rerr := d.Connectors.ToolReferences(ctx, orgID, toolID); rerr == nil {
		for _, p := range refs.ApprovalPolicies {
			if p.Match == "name" || !byNameOnly {
				details = append(details, &huma.ErrorDetail{Location: "references.approvalPolicies", Message: p.Name, Value: p.ID})
			}
		}
	}
	return huma.Error409Conflict(err.Error(), details...)
}

// editorName is how the person who last edited a tool is shown: their
// name, else their address. It is empty when they cannot be looked up,
// for instance after they left the organisation.
func (d Deps) editorName(ctx context.Context, orgID, userID string) string {
	if d.Identity == nil || userID == "" {
		return ""
	}
	u, err := d.Identity.UserByID(ctx, orgID, userID)
	if err != nil {
		return ""
	}
	if u.Name != "" {
		return u.Name
	}
	return u.Email
}
