package connector

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

// Tool errors. The HTTP layer maps each one to a status; see humaErr.
var (
	// ErrToolNotFound is returned for unknown or invisible tools.
	ErrToolNotFound = errors.New("tool not found")
	// ErrToolNameTaken means another tool on the same connector already
	// has the name.
	ErrToolNameTaken = errors.New("a tool with this name already exists on this connector")
	// ErrVersionConflict means the tool changed since the caller read it.
	ErrVersionConflict = errors.New("the tool was changed by someone else; reload it and try again")
	// ErrToolNotDeletable means the tool came from the catalog or an
	// import. Those can only be disabled.
	ErrToolNotDeletable = errors.New("only custom tools can be deleted; disable this one instead")
	// ErrReferencesNotAcknowledged means a rename or delete would break
	// approval policies that match the tool by name, and the caller did
	// not say it accepts that.
	ErrReferencesNotAcknowledged = errors.New("approval policies refer to this tool by name; acknowledge the references to continue")
)

// Tool sources: where a stored tool came from.
const (
	ToolSourceCatalog = "catalog"
	ToolSourceImport  = "import"
	ToolSourceCustom  = "custom"
)

// Tool is a stored tool.
type Tool struct {
	ID           string        `json:"id"`
	ConnectorID  string        `json:"connectorId"`
	Name         string        `json:"name"`
	Definition   *adapter.Tool `json:"definition"`
	OperationID  string        `json:"operationId,omitempty"`
	Enabled      bool          `json:"enabled"`
	DeprecatedAt *time.Time    `json:"deprecatedAt,omitempty"`
	Version      int64         `json:"version"`
	// Source is one of ToolSourceCatalog, ToolSourceImport, ToolSourceCustom.
	Source string `json:"source"`
	// EditedAt and EditedBy are set once someone edits the definition by
	// hand; a catalog re-sync leaves such a tool alone.
	EditedAt  *time.Time `json:"editedAt,omitempty"`
	EditedBy  string     `json:"editedBy,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
}

// InvalidToolError carries the issues that stop a definition from being
// saved. Issues may include warnings; at least one is an error.
type InvalidToolError struct {
	Issues []adapter.Issue
}

// Error lists the error-severity issues.
func (e *InvalidToolError) Error() string {
	var b strings.Builder
	b.WriteString("invalid tool definition")
	sep := ": "
	for _, i := range e.Issues {
		if i.Severity != adapter.SeverityError {
			continue
		}
		b.WriteString(sep)
		if i.Field != "" {
			b.WriteString(i.Field)
			b.WriteString(": ")
		}
		b.WriteString(i.Message)
		sep = "; "
	}
	return b.String()
}

// ToolInput is a tool create or update.
type ToolInput struct {
	// Definition is the whole tool; its Name is the tool's name.
	Definition *adapter.Tool
	// Enabled leaves the flag unchanged when nil (create defaults to true).
	Enabled *bool
	// ExpectedVersion must equal the stored version on update; ignored on
	// create.
	ExpectedVersion int64
	// AcknowledgeReferences lets a rename go ahead although name-matched
	// approval policies will stop matching.
	AcknowledgeReferences bool
	// ActorID names who made the change.
	ActorID string
}

// ToolReferences lists what refers to a tool and would be affected by a
// rename or delete.
type ToolReferences struct {
	// ApprovalPolicies match the tool by name or are scoped to it.
	ApprovalPolicies []PolicyRef
	// AccessRules is how many role allow/deny rules name the tool; they
	// are removed with it.
	AccessRules int
	// DLPPolicies is how many DLP policies are scoped to the tool; they
	// are removed with it.
	DLPPolicies int
}

// PolicyRef is one approval policy that refers to a tool.
type PolicyRef struct {
	ID      string
	Name    string
	Enabled bool
	// Match is "name" for a policy matching the tool by name (it breaks on
	// rename or delete) or "scope" for one scoped to the tool's ID.
	Match string
}

// GetTool loads one tool.
func (s *Service) GetTool(ctx context.Context, orgID, toolID string) (*Tool, error) {
	return nil, errors.New("not implemented")
}

// CheckTool validates a definition for a connector without saving it.
// toolID is the tool being edited, or empty for a new one. The error is
// only for failures to check; problems with the definition are issues.
func (s *Service) CheckTool(ctx context.Context, orgID, connectorID, toolID string, def *adapter.Tool) ([]adapter.Issue, error) {
	return nil, errors.New("not implemented")
}

// CreateTool adds a custom tool to a connector. It returns the stored tool
// and any warnings; error-severity issues come back as *InvalidToolError.
func (s *Service) CreateTool(ctx context.Context, orgID, connectorID string, in ToolInput) (*Tool, []adapter.Issue, error) {
	return nil, nil, errors.New("not implemented")
}

// UpdateTool replaces a tool's definition. It returns the stored tool and
// any warnings; error-severity issues come back as *InvalidToolError.
func (s *Service) UpdateTool(ctx context.Context, orgID, toolID string, in ToolInput) (*Tool, []adapter.Issue, error) {
	return nil, nil, errors.New("not implemented")
}

// DeleteTool removes a custom tool.
func (s *Service) DeleteTool(ctx context.Context, orgID, toolID string, acknowledgeReferences bool, actorID string) error {
	return errors.New("not implemented")
}

// ToolReferences lists what refers to a tool.
func (s *Service) ToolReferences(ctx context.Context, orgID, toolID string) (*ToolReferences, error) {
	return nil, errors.New("not implemented")
}

// BehaviourChanged reports whether an edit changes what a call does
// (operation, response, output, timeout, rate limit, proxy, annotation
// hints) rather than only how the tool is described.
func BehaviourChanged(before, after *adapter.Tool) bool {
	return false
}
