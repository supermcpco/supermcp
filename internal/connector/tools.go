package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/tenant"
	"github.com/supermcpco/supermcp/internal/transform"
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

// toolRevision is what a tool revision stores. The definition is a string
// in stored key order: a snapshot is a JSON object whose keys the audit
// encoding sorts, which would reorder the input schema's properties on a
// restore.
type toolRevision struct {
	ID          string `json:"id"`
	ConnectorID string `json:"connectorId"`
	Name        string `json:"name"`
	Source      string `json:"source"`
	Enabled     bool   `json:"enabled"`
	Version     int64  `json:"version"`
	Definition  string `json:"definition"`
}

// Match values of a PolicyRef.
const (
	policyMatchName  = "name"
	policyMatchScope = "scope"
)

// uniqueViolation is the Postgres error code for a unique constraint.
const uniqueViolation = "23505"

const selectTool = `SELECT t.id, t.connector_id, t.name, t.definition, COALESCE(t.operation_id,''), t.enabled, t.deprecated_at,
	t.version, t.source, t.edited_at, COALESCE(t.edited_by,''), t.created_at, t.updated_at FROM tools t`

// Tools lists a connector's tools.
func (s *Service) Tools(ctx context.Context, orgID, connectorID string) ([]*Tool, error) {
	var out []*Tool
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectTool+` WHERE t.connector_id = $1 ORDER BY t.name`, connectorID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanTool(rows)
			if err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	if out == nil {
		out = []*Tool{}
	}
	return out, err
}

// GetTool loads one tool.
func (s *Service) GetTool(ctx context.Context, orgID, toolID string) (*Tool, error) {
	var t *Tool
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		t, err = getToolTx(ctx, tx, toolID, "")
		return err
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

// CheckTool validates a definition for a connector without saving it.
// toolID is the tool being edited, or empty for a new one. The error is
// only for failures to check; problems with the definition are issues.
func (s *Service) CheckTool(ctx context.Context, orgID, connectorID, toolID string, def *adapter.Tool) ([]adapter.Issue, error) {
	if def == nil {
		return []adapter.Issue{definitionRequired()}, nil
	}
	var issues []adapter.Issue
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		c, err := scanConnector(tx.QueryRow(ctx, selectConnector+` WHERE c.id = $1`, connectorID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var before *adapter.Tool
		if toolID != "" {
			t, err := getToolTx(ctx, tx, toolID, "")
			if err != nil {
				return err
			}
			if t.ConnectorID != connectorID {
				return ErrToolNotFound
			}
			before = t.Definition
		}
		issues, err = checkToolTx(ctx, tx, c, toolID, before, def)
		return err
	})
	if err != nil {
		return nil, err
	}
	return issues, nil
}

// CreateTool adds a custom tool to a connector. It returns the stored tool
// and any warnings; error-severity issues come back as *InvalidToolError.
func (s *Service) CreateTool(ctx context.Context, orgID, connectorID string, in ToolInput) (*Tool, []adapter.Issue, error) {
	if in.Definition == nil {
		return nil, nil, &InvalidToolError{Issues: []adapter.Issue{definitionRequired()}}
	}
	id := s.NewID()
	var warnings []adapter.Issue
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		c, err := lockConnector(ctx, tx, connectorID)
		if err != nil {
			return err
		}
		issues, err := checkToolTx(ctx, tx, c, "", nil, in.Definition)
		if err != nil {
			return err
		}
		if hasErrors(issues) {
			return &InvalidToolError{Issues: issues}
		}
		warnings = issues
		def, err := DefinitionJSON(in.Definition)
		if err != nil {
			return fmt.Errorf("encode tool: %w", err)
		}
		enabled := in.Enabled == nil || *in.Enabled
		if err := insertToolRow(ctx, tx, id, c, in.Definition.Name, def, ToolSourceCustom, enabled); err != nil {
			return err
		}
		if err := bumpConnectorTx(ctx, tx, c.ID); err != nil {
			return err
		}
		if err := bumpServersTx(ctx, tx, c.ID); err != nil {
			return err
		}
		after, err := getToolTx(ctx, tx, id, "")
		if err != nil {
			return err
		}
		snap, err := snapshotTool(after)
		if err != nil {
			return err
		}
		return s.record(ctx, tx, "tool", id, "create", snap, audit.Created(snap), in.ActorID)
	})
	if err != nil {
		return nil, nil, err
	}
	t, err := s.GetTool(ctx, orgID, id)
	if err != nil {
		return nil, nil, err
	}
	return t, warningsOf(warnings), nil
}

// UpdateTool replaces a tool's definition. It returns the stored tool and
// any warnings; error-severity issues come back as *InvalidToolError.
func (s *Service) UpdateTool(ctx context.Context, orgID, toolID string, in ToolInput) (*Tool, []adapter.Issue, error) {
	if in.Definition == nil {
		return nil, nil, &InvalidToolError{Issues: []adapter.Issue{definitionRequired()}}
	}
	var warnings []adapter.Issue
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		c, before, err := lockTool(ctx, tx, toolID)
		if err != nil {
			return err
		}
		if in.ExpectedVersion != 0 && in.ExpectedVersion != before.Version {
			return ErrVersionConflict
		}
		issues, err := checkToolTx(ctx, tx, c, toolID, before.Definition, in.Definition)
		if err != nil {
			return err
		}
		if hasErrors(issues) {
			return &InvalidToolError{Issues: issues}
		}
		warnings = issues
		if in.Definition.Name != before.Name {
			refs, err := toolReferencesTx(ctx, tx, before)
			if err != nil {
				return err
			}
			if refs.byName() && !in.AcknowledgeReferences {
				return ErrReferencesNotAcknowledged
			}
		}
		def, err := DefinitionJSON(in.Definition)
		if err != nil {
			return fmt.Errorf("encode tool: %w", err)
		}
		enabled := before.Enabled
		if in.Enabled != nil {
			enabled = *in.Enabled
		}
		if _, err := tx.Exec(ctx, `UPDATE tools SET name = $2, definition = $3, enabled = $4, version = version + 1,
			updated_at = now(), edited_at = now(), edited_by = NULLIF($5, '') WHERE id = $1`,
			toolID, in.Definition.Name, def, enabled, in.ActorID); err != nil {
			return mapToolWriteError(err)
		}
		if BehaviourChanged(before.Definition, in.Definition) {
			if err := cancelApprovalsTx(ctx, tx, toolID, "the tool's definition changed"); err != nil {
				return err
			}
		}
		if err := bumpConnectorTx(ctx, tx, c.ID); err != nil {
			return err
		}
		if err := bumpServersTx(ctx, tx, c.ID); err != nil {
			return err
		}
		after, err := getToolTx(ctx, tx, toolID, "")
		if err != nil {
			return err
		}
		beforeSnap, err := snapshotTool(before)
		if err != nil {
			return err
		}
		afterSnap, err := snapshotTool(after)
		if err != nil {
			return err
		}
		if err := s.recordBaseline(ctx, tx, "tool", toolID, beforeSnap); err != nil {
			return err
		}
		return s.record(ctx, tx, "tool", toolID, "update", afterSnap, audit.Changes(beforeSnap, afterSnap), in.ActorID)
	})
	if err != nil {
		return nil, nil, err
	}
	t, err := s.GetTool(ctx, orgID, toolID)
	if err != nil {
		return nil, nil, err
	}
	return t, warningsOf(warnings), nil
}

// DeleteTool removes a custom tool.
func (s *Service) DeleteTool(ctx context.Context, orgID, toolID string, acknowledgeReferences bool, actorID string) error {
	return s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		c, before, err := lockTool(ctx, tx, toolID)
		if err != nil {
			return err
		}
		if before.Source != ToolSourceCustom {
			return ErrToolNotDeletable
		}
		refs, err := toolReferencesTx(ctx, tx, before)
		if err != nil {
			return err
		}
		// Every approval policy that names the tool, by name or by scope,
		// stops matching anything once it is gone.
		if len(refs.ApprovalPolicies) > 0 && !acknowledgeReferences {
			return ErrReferencesNotAcknowledged
		}
		// DLP policies scoped to the tool go with it by foreign key.
		if _, err := tx.Exec(ctx, `DELETE FROM tools WHERE id = $1`, toolID); err != nil {
			return err
		}
		// A request for a tool that no longer exists can never run.
		if err := cancelApprovalsTx(ctx, tx, toolID, "the tool was deleted"); err != nil {
			return err
		}
		if err := bumpConnectorTx(ctx, tx, c.ID); err != nil {
			return err
		}
		if err := bumpServersTx(ctx, tx, c.ID); err != nil {
			return err
		}
		// tool_access_rules has no foreign key to tools.
		if _, err := tx.Exec(ctx, `DELETE FROM tool_access_rules WHERE tool_id = $1`, toolID); err != nil {
			return err
		}
		snap, err := snapshotTool(before)
		if err != nil {
			return err
		}
		if err := s.recordBaseline(ctx, tx, "tool", toolID, snap); err != nil {
			return err
		}
		return s.record(ctx, tx, "tool", toolID, "delete", snap, audit.Deleted(snap), actorID)
	})
}

// SetToolEnabled switches a tool on or off. Like every tool write it locks
// the connector before the tool, bumps the tool, connector and server
// versions so cached tool lists rebuild, and records a revision.
func (s *Service) SetToolEnabled(ctx context.Context, orgID, toolID string, enabled bool, actorID string) error {
	return s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		c, before, err := lockTool(ctx, tx, toolID)
		if err != nil {
			return err
		}
		if before.Enabled == enabled {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE tools SET enabled = $2, version = version + 1, updated_at = now() WHERE id = $1`, toolID, enabled); err != nil {
			return err
		}
		if err := bumpConnectorTx(ctx, tx, c.ID); err != nil {
			return err
		}
		if err := bumpServersTx(ctx, tx, c.ID); err != nil {
			return err
		}
		beforeSnap, err := snapshotTool(before)
		if err != nil {
			return err
		}
		afterSnap := beforeSnap
		afterSnap.Enabled = enabled
		afterSnap.Version++
		if err := s.recordBaseline(ctx, tx, "tool", toolID, beforeSnap); err != nil {
			return err
		}
		return s.record(ctx, tx, "tool", toolID, "update", afterSnap, audit.Changes(beforeSnap, afterSnap), actorID)
	})
}

// ToolReferences lists what refers to a tool.
func (s *Service) ToolReferences(ctx context.Context, orgID, toolID string) (*ToolReferences, error) {
	var refs *ToolReferences
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		t, err := getToolTx(ctx, tx, toolID, "")
		if err != nil {
			return err
		}
		refs, err = toolReferencesTx(ctx, tx, t)
		return err
	})
	if err != nil {
		return nil, err
	}
	return refs, nil
}

// BehaviourChanged reports whether an edit changes what a call does
// (operation, response, output, timeout, rate limit, proxy, annotation
// hints) rather than only how the tool is described.
func BehaviourChanged(before, after *adapter.Tool) bool {
	if before == nil || after == nil {
		return before != after
	}
	b, errB := behaviourJSON(before)
	a, errA := behaviourJSON(after)
	if errB != nil || errA != nil {
		// Unable to tell: treat it as a change, which is the safe side.
		return true
	}
	return !bytes.Equal(a, b)
}

// behaviourJSON encodes the parts of a definition that decide what a call
// does, with object keys sorted so that reordering is not a change.
func behaviourJSON(t *adapter.Tool) ([]byte, error) {
	var hints struct {
		ReadOnly, Destructive, Idempotent, OpenWorld *bool
	}
	if t.Annotations != nil {
		hints.ReadOnly, hints.Destructive = t.Annotations.ReadOnlyHint, t.Annotations.DestructiveHint
		hints.Idempotent, hints.OpenWorld = t.Annotations.IdempotentHint, t.Annotations.OpenWorldHint
	}
	raw, err := json.Marshal(struct {
		Operation adapter.Operation
		Response  *adapter.Response
		Output    *adapter.Node
		Timeout   adapter.Duration
		RateLimit *adapter.RateLimit
		Proxy     *bool
		Hints     any
	}{t.Operation, t.Response, t.Output, t.Timeout, t.RateLimit, t.Proxy, hints})
	if err != nil {
		return nil, err
	}
	// A round trip through a generic value sorts every object's keys.
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// byName reports whether a policy matches the tool by its name.
func (r *ToolReferences) byName() bool {
	for _, p := range r.ApprovalPolicies {
		if p.Match == policyMatchName {
			return true
		}
	}
	return false
}

// lockConnector reads a connector and takes its row lock. NO KEY UPDATE is
// the lock an UPDATE of the row takes: it queues every other tool write
// and a connector delete, but not the key-share lock that linking the
// connector to a server takes while holding that server's row, which
// would otherwise deadlock against bumpServersTx.
func lockConnector(ctx context.Context, tx pgx.Tx, connectorID string) (*Connector, error) {
	c, err := scanConnector(tx.QueryRow(ctx, selectConnector+` WHERE c.id = $1 FOR NO KEY UPDATE OF c`, connectorID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// lockTool locks a tool's connector and then the tool, in that order: the
// order a connector delete cascades in, so the two cannot deadlock.
func lockTool(ctx context.Context, tx pgx.Tx, toolID string) (*Connector, *Tool, error) {
	var connectorID string
	err := tx.QueryRow(ctx, `SELECT connector_id FROM tools WHERE id = $1`, toolID).Scan(&connectorID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrToolNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	c, err := lockConnector(ctx, tx, connectorID)
	if errors.Is(err, ErrNotFound) {
		// The connector went, and the tool with it, between the two reads.
		return nil, nil, ErrToolNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	t, err := getToolTx(ctx, tx, toolID, " FOR NO KEY UPDATE")
	if err != nil {
		return nil, nil, err
	}
	return c, t, nil
}

// getToolTx reads one tool; lock is appended to the query.
func getToolTx(ctx context.Context, tx pgx.Tx, toolID, lock string) (*Tool, error) {
	t, err := scanTool(tx.QueryRow(ctx, selectTool+` WHERE t.id = $1`+lock, toolID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrToolNotFound
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

func scanTool(row pgx.Row) (*Tool, error) {
	var t Tool
	var def []byte
	if err := row.Scan(&t.ID, &t.ConnectorID, &t.Name, &def, &t.OperationID, &t.Enabled, &t.DeprecatedAt, &t.Version,
		&t.Source, &t.EditedAt, &t.EditedBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	td, err := ParseToolJSON(def)
	if err != nil {
		return nil, err
	}
	t.Definition = td
	return &t, nil
}

func insertToolRow(ctx context.Context, tx pgx.Tx, id string, c *Connector, name string, def []byte, source string, enabled bool) error {
	_, err := tx.Exec(ctx, `INSERT INTO tools (id, connector_id, organization_id, name, definition, enabled, source) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, c.ID, c.OrgID, name, def, enabled, source)
	return mapToolWriteError(err)
}

// mapToolWriteError turns the (connector_id, name) unique violation into
// ErrToolNameTaken. It catches the race the name check before it cannot.
func mapToolWriteError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return ErrToolNameTaken
	}
	return err
}

func bumpConnectorTx(ctx context.Context, tx pgx.Tx, connectorID string) error {
	_, err := tx.Exec(ctx, `UPDATE connectors SET version = version + 1, updated_at = now() WHERE id = $1`, connectorID)
	return err
}

// bumpServersTx moves the version of every MCP server the connector is on,
// which is what the served tool list is cached under.
func bumpServersTx(ctx context.Context, tx pgx.Tx, connectorID string) error {
	_, err := tx.Exec(ctx, `UPDATE mcp_servers SET version = version + 1, updated_at = now()
		WHERE id IN (SELECT server_id FROM mcp_server_connectors WHERE connector_id = $1)`, connectorID)
	return err
}

// cancelApprovalsTx withdraws the requests for a tool that could still run:
// an approval replays by tool id, so without this a person's yes to the
// old definition would run the new one.
func cancelApprovalsTx(ctx context.Context, tx pgx.Tx, toolID, reason string) error {
	_, err := tx.Exec(ctx, `UPDATE approval_requests SET state = 'cancelled', cancelled_at = now(), reason = $2
		WHERE tool_id = $1 AND state IN ('pending', 'approved')`, toolID, reason)
	if err != nil {
		return fmt.Errorf("cancel approval requests: %w", err)
	}
	return nil
}

// toolReferencesTx finds what refers to a tool. A policy matches by name
// when it triggers on the tool's name and its scope reaches the tool (the
// organisation, a server the connector is on, the connector, or the tool);
// it matches by scope when it is hung on the tool's id.
func toolReferencesTx(ctx context.Context, tx pgx.Tx, t *Tool) (*ToolReferences, error) {
	refs := &ToolReferences{ApprovalPolicies: []PolicyRef{}}
	rows, err := tx.Query(ctx, `SELECT p.id, p.name, p.enabled,
			CASE WHEN p.trigger_kind = 'tool' AND p.tool_name = $2 THEN 'name' ELSE 'scope' END
		FROM approval_policies p
		WHERE (p.trigger_kind = 'tool' AND p.tool_name = $2 AND (
				p.scope_kind = 'organization'
				OR (p.scope_kind = 'connector' AND p.scope_id = $3)
				OR (p.scope_kind = 'tool' AND p.scope_id = $1)
				OR (p.scope_kind = 'server' AND p.scope_id IN (SELECT server_id FROM mcp_server_connectors WHERE connector_id = $3))))
		   OR (p.scope_kind = 'tool' AND p.scope_id = $1)
		ORDER BY p.name, p.id`, t.ID, t.Name, t.ConnectorID)
	if err != nil {
		return nil, fmt.Errorf("read approval policies: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p PolicyRef
		if err := rows.Scan(&p.ID, &p.Name, &p.Enabled, &p.Match); err != nil {
			return nil, err
		}
		refs.ApprovalPolicies = append(refs.ApprovalPolicies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM tool_access_rules WHERE tool_id = $1),
			(SELECT count(*) FROM dlp_policies WHERE tool_id = $1)`, t.ID).Scan(&refs.AccessRules, &refs.DLPPolicies); err != nil {
		return nil, fmt.Errorf("count tool references: %w", err)
	}
	return refs, nil
}

// checkToolTx runs ValidateTool and the checks that need the connector and
// the database. before is the stored definition of the tool being edited,
// nil for a new one.
func checkToolTx(ctx context.Context, tx pgx.Tx, c *Connector, toolID string, before, def *adapter.Tool) ([]adapter.Issue, error) {
	tt := c.Transport.Type
	issues := adapter.ValidateTool(def, tt)
	errorAt := func(field, rule, msg string) {
		issues = append(issues, adapter.Issue{Rule: rule, Severity: adapter.SeverityError, Message: msg, Field: field})
	}
	warnAt := func(field, rule, msg string) {
		issues = append(issues, adapter.Issue{Rule: rule, Severity: adapter.SeverityWarning, Message: msg, Field: field})
	}

	if def.Response != nil && def.Response.Transform != nil && len(def.Response.Transform.JMESPath) > transform.MaxExpressionLength {
		errorAt("response.transform.jmespath", "transform-length",
			fmt.Sprintf("the transform is %d characters; the limit is %d", len(def.Response.Transform.JMESPath), transform.MaxExpressionLength))
	}
	if tt == adapter.TransportHTTP || tt == adapter.TransportSOAP {
		if host, ok := pathHost(def.Operation.Path); ok {
			known, err := knownHostsTx(ctx, tx, c, before)
			if err != nil {
				return nil, err
			}
			if !known[host] {
				errorAt("operation.path", "operation-host",
					fmt.Sprintf("operation.path sends the connector's credentials to %s, which is not the connector's host or one its tools already use", host))
			}
		}
	}

	var taken bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tools WHERE connector_id = $1 AND name = $2 AND id <> $3)`,
		c.ID, def.Name, toolID).Scan(&taken); err != nil {
		return nil, fmt.Errorf("check tool name: %w", err)
	}
	if taken {
		errorAt("name", "tool-name-unique", fmt.Sprintf("the connector already has a tool called %s", def.Name))
	}

	if used := adapter.ToolPlaceholderEnv(def); len(used) > 0 {
		known, err := knownEnvTx(ctx, tx, c)
		if err != nil {
			return nil, err
		}
		for _, name := range used {
			if !known[name] {
				warnAt("operation", "env-unknown", fmt.Sprintf("{{env.%s}} is not a credential of this connector; it renders empty until one is set", name))
			}
		}
	}

	shared, err := sharedNameConnectorsTx(ctx, tx, c.ID, def.Name)
	if err != nil {
		return nil, err
	}
	for _, name := range shared {
		warnAt("name", "tool-name-shared-server", fmt.Sprintf("connector %s on the same MCP server also has a tool called %s", name, def.Name))
	}

	if tt == adapter.TransportSOAP || tt == adapter.TransportMCP {
		warnAt("", "preview-unsupported", fmt.Sprintf("a dry-run preview is not available for %s connectors", tt))
	}
	return issues, nil
}

// knownHostsTx is where a tool of this connector may send requests: the
// base URL's host, the hosts its stored tools already use, and the host
// the edited tool had.
func knownHostsTx(ctx context.Context, tx pgx.Tx, c *Connector, before *adapter.Tool) (map[string]bool, error) {
	known := map[string]bool{}
	if h, ok := pathHost(c.Transport.BaseURL); ok {
		known[h] = true
	}
	if before != nil {
		if h, ok := pathHost(before.Operation.Path); ok {
			known[h] = true
		}
	}
	rows, err := tx.Query(ctx, `SELECT definition->'operation'->>'path' FROM tools
		WHERE connector_id = $1 AND COALESCE(definition->'operation'->>'path', '') <> ''`, c.ID)
	if err != nil {
		return nil, fmt.Errorf("read tool hosts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		if h, ok := pathHost(p); ok {
			known[h] = true
		}
	}
	return known, rows.Err()
}

// knownEnvTx is the set of {{env.X}} names the connector can fill: its
// stored credentials and the ones its transport and auth refer to.
func knownEnvTx(ctx context.Context, tx pgx.Tx, c *Connector) (map[string]bool, error) {
	known := map[string]bool{}
	for _, name := range referencedCredentials(c) {
		known[name] = true
	}
	rows, err := tx.Query(ctx, `SELECT name FROM connector_credentials WHERE connector_id = $1`, c.ID)
	if err != nil {
		return nil, fmt.Errorf("read credential names: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		known[name] = true
	}
	return known, rows.Err()
}

// sharedNameConnectorsTx names the other connectors that share an MCP
// server with this one and have a tool of the same name.
func sharedNameConnectorsTx(ctx context.Context, tx pgx.Tx, connectorID, name string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT c.name FROM tools t JOIN connectors c ON c.id = t.connector_id
		WHERE t.name = $2 AND t.connector_id <> $1 AND t.connector_id IN (
			SELECT o.connector_id FROM mcp_server_connectors m JOIN mcp_server_connectors o ON o.server_id = m.server_id
			WHERE m.connector_id = $1)
		ORDER BY c.name`, connectorID, name)
	if err != nil {
		return nil, fmt.Errorf("read tools sharing a server: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// pathHost returns where an operation path or base URL points, when it can
// point anywhere other than the connector's base URL: the lower-cased host
// of an absolute URL (a templated host is kept as written), or the leading
// raw placeholder of a path that renders to a whole URL. Relative paths,
// and paths whose leading placeholder is path-escaped, return false.
func pathHost(p string) (string, bool) {
	p = strings.TrimSpace(p)
	low := strings.ToLower(p)
	for _, scheme := range []string{"http://", "https://"} {
		if strings.HasPrefix(low, scheme) {
			rest := p[len(scheme):]
			end := len(rest)
			if i := strings.IndexAny(rest, "/?#"); i >= 0 {
				end = i
			}
			host := rest[:end]
			// Userinfo does not change where the request goes.
			if i := strings.LastIndex(host, "@"); i >= 0 && !strings.Contains(host[i:], "}}") {
				host = host[i+1:]
			}
			if strings.Contains(host, "{{") {
				return host, true
			}
			return strings.ToLower(host), true
		}
	}
	// A path that starts with an unescaped placeholder can render to an
	// absolute URL, which the HTTP engine then uses as is.
	if strings.HasPrefix(p, "{{") {
		end := strings.Index(p, "}}")
		if end < 0 {
			return "", false
		}
		ph := p[:end+2]
		if strings.Contains(ph, "raw") {
			return ph, true
		}
	}
	return "", false
}

func snapshotTool(t *Tool) (toolRevision, error) {
	def, err := DefinitionJSON(t.Definition)
	if err != nil {
		return toolRevision{}, fmt.Errorf("encode tool: %w", err)
	}
	return toolRevision{ID: t.ID, ConnectorID: t.ConnectorID, Name: t.Name, Source: t.Source,
		Enabled: t.Enabled, Version: t.Version, Definition: string(def)}, nil
}

func definitionRequired() adapter.Issue {
	return adapter.Issue{Rule: "definition-required", Severity: adapter.SeverityError, Message: "a tool definition is required"}
}

func hasErrors(issues []adapter.Issue) bool {
	for _, i := range issues {
		if i.Severity == adapter.SeverityError {
			return true
		}
	}
	return false
}

func warningsOf(issues []adapter.Issue) []adapter.Issue {
	out := make([]adapter.Issue, 0, len(issues))
	for _, i := range issues {
		if i.Severity != adapter.SeverityError {
			out = append(out, i)
		}
	}
	return out
}
