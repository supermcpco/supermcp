package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/engine"
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

func (d Deps) toolRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "tools-get", Method: http.MethodGet, Path: "/api/v1/tools/{id}",
		Summary: "Get a tool with its definition", Tags: []string{"tools"}, Security: sessionSecurity},
		func(ctx context.Context, in *toolIDInput) (*toolDetailOutput, error) {
			return nil, huma.Error501NotImplemented("not yet")
		})

	huma.Register(api, huma.Operation{OperationID: "tools-create", Method: http.MethodPost, Path: "/api/v1/connectors/{id}/tools",
		Summary: "Add a custom tool to a connector", Tags: []string{"tools"}, Security: sessionSecurity,
		DefaultStatus: http.StatusCreated},
		func(ctx context.Context, in *toolCreateInput) (*toolWriteOutput, error) {
			return nil, huma.Error501NotImplemented("not yet")
		})

	huma.Register(api, huma.Operation{OperationID: "tools-update", Method: http.MethodPut, Path: "/api/v1/tools/{id}",
		Summary: "Replace a tool's definition", Tags: []string{"tools"}, Security: sessionSecurity},
		func(ctx context.Context, in *toolUpdateInput) (*toolWriteOutput, error) {
			return nil, huma.Error501NotImplemented("not yet")
		})

	huma.Register(api, huma.Operation{OperationID: "tools-delete", Method: http.MethodDelete, Path: "/api/v1/tools/{id}",
		Summary: "Delete a custom tool", Tags: []string{"tools"}, Security: sessionSecurity,
		DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *toolDeleteInput) (*struct{}, error) {
			return nil, huma.Error501NotImplemented("not yet")
		})

	huma.Register(api, huma.Operation{OperationID: "tools-references", Method: http.MethodGet, Path: "/api/v1/tools/{id}/references",
		Summary: "List what refers to a tool", Tags: []string{"tools"}, Security: sessionSecurity},
		func(ctx context.Context, in *toolIDInput) (*toolReferencesOutput, error) {
			return nil, huma.Error501NotImplemented("not yet")
		})

	huma.Register(api, huma.Operation{OperationID: "tools-draft-dry-run", Method: http.MethodPost, Path: "/api/v1/connectors/{id}/tools/dry-run",
		Summary: "Check an unsaved tool definition and render the request it would send", Tags: []string{"tools"},
		Security: sessionSecurity},
		func(ctx context.Context, in *toolDraftInput) (*toolDraftOutput, error) {
			return nil, huma.Error501NotImplemented("not yet")
		})
}

// --- helpers -------------------------------------------------------------------

// toolToDTO is the list shape of a tool.
// TODO(WP-B): fill Annotations from tool.Derive.
func toolToDTO(t *connector.Tool) toolDTO {
	return toolDTO{ID: t.ID, Name: t.Name, Description: t.Definition.Description, Enabled: t.Enabled,
		Source: t.Source, Edited: t.EditedAt != nil, Version: t.Version}
}
