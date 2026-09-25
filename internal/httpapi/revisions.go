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
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/governance"
	"github.com/supermcpco/supermcp/internal/mcpserver"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// --- revisions -------------------------------------------------------------

// Reading the history is as privileged as reading the thing it is the
// history of; putting an earlier version back is not, and asks for
// revisions:rollback on top.
//
// A restore goes through the service that owns the entity, never at the
// connectors or mcp_servers tables directly: that service applies its own
// rules and writes the new revision, so the correction is recorded the
// same way the mistake was.

// revisionKind ties a URL segment to the entity it names. The routes are
// registered per kind rather than behind a {kind} parameter so that each
// one carries its own permission and its own response shape, and so that
// /api/v1/connectors/{id}/revisions cannot be resolved by accident.
//
// op names the operations, and is the path wherever the path has no
// slash in it. edit is the permission that changes the entity, which a
// restore asks for on top of revisions:rollback: putting back an earlier
// sign-in provider is changing how people sign in, and somebody allowed
// to roll back a connector is not thereby allowed to do that. The kinds
// that predate it leave it empty and ask for revisions:rollback alone.
type revisionKind struct {
	kind governance.Kind
	path string
	op   string
	tag  string
	read authz.Permission
	edit authz.Permission
}

var (
	connectorRevisions = revisionKind{kind: governance.KindConnector, path: "connectors", op: "connectors",
		tag: "connectors", read: authz.ConnectorsRead}
	toolRevisions = revisionKind{kind: governance.KindTool, path: "tools", op: "tools",
		tag: "connectors", read: authz.ConnectorsRead}
	serverRevisions = revisionKind{kind: governance.KindServer, path: "servers", op: "servers",
		tag: "servers", read: authz.ServersRead}
	roleRevisions = revisionKind{kind: governance.KindRole, path: "roles", op: "roles",
		tag: "roles", read: authz.RolesRead}
	// The policies and the providers are read with the permission that
	// lists them, so the history shows nobody a rule they could not
	// already see.
	dlpRevisions = revisionKind{kind: governance.KindDLPPolicy, path: "dlp/policies", op: "dlp-policies",
		tag: "dlp", read: authz.ConnectorsRead, edit: authz.DLPManage}
	approvalPolicyRevisions = revisionKind{kind: governance.KindApprovalPolicy, path: "approval-policies",
		op: "approval-policies", tag: "approvals", read: authz.ApprovalsDecide, edit: authz.OrgSettingsManage}
	idpRevisions = revisionKind{kind: governance.KindIdentityProvider, path: "idps", op: "idps",
		tag: "identity", read: authz.IdpManage, edit: authz.IdpManage}
	samlRevisions = revisionKind{kind: governance.KindSAMLProvider, path: "saml-providers", op: "saml-providers",
		tag: "identity", read: authz.IdpManage, edit: authz.IdpManage}

	revisionKinds = []revisionKind{connectorRevisions, toolRevisions, serverRevisions, roleRevisions,
		dlpRevisions, approvalPolicyRevisions, idpRevisions, samlRevisions}
)

// A role applies across the whole organisation rather than to one server
// or connector, so its resource names nothing: reading its history is as
// privileged as reading the roles. The policies and providers are the
// same.
func (k revisionKind) resource(id string) authz.Resource {
	switch k.kind {
	case governance.KindConnector:
		return authz.Resource{ConnectorID: id}
	case governance.KindTool:
		return authz.Resource{ToolID: id}
	case governance.KindServer:
		return authz.Resource{ServerID: id}
	default:
		return authz.Resource{}
	}
}

type revisionDTO struct {
	ID           string         `json:"id"`
	Kind         string         `json:"kind" enum:"connector,tool,server,role,dlp_policy,approval_policy,identity_provider,saml_provider"`
	EntityID     string         `json:"entityId"`
	Revision     int            `json:"revision"`
	Action       string         `json:"action" enum:"create,update,delete"`
	ActorID      string         `json:"actorId,omitempty"`
	ActorDisplay string         `json:"actorDisplay,omitempty"`
	CreatedAt    time.Time      `json:"createdAt"`
	Diff         *audit.Diff    `json:"diff,omitempty"`
	Snapshot     map[string]any `json:"snapshot,omitempty" doc:"The entity as it stood after this change; only on a single revision. A connector's secret auth and transport values read ***"`
}

type revisionListInput struct {
	ID     string `path:"id"`
	Before int    `query:"before" doc:"Continue below this revision number, taken from the previous page's nextBefore"`
	Limit  int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
}

type revisionListOutput struct {
	Body struct {
		Revisions  []revisionDTO `json:"revisions" nullable:"false"`
		NextBefore int           `json:"nextBefore" doc:"Pass as before for the next page; zero at the start of the history"`
	}
}

type revisionGetInput struct {
	ID       string `path:"id"`
	Revision int    `path:"revision" minimum:"1"`
}

// redact hides the secrets a connector revision can hold in its auth and
// transport, in the diff and the snapshot alike. Only the response is
// redacted: a restore reads the stored snapshot, so it puts the real
// values back.
func (k revisionKind) redact(dto revisionDTO) revisionDTO {
	if k.kind != governance.KindConnector {
		return dto
	}
	dto.Snapshot = redactConnectorFields(dto.Snapshot)
	if dto.Diff != nil {
		dto.Diff = &audit.Diff{Before: redactConnectorFields(dto.Diff.Before), After: redactConnectorFields(dto.Diff.After)}
	}
	return dto
}

// redactConnectorFields returns a copy of a connector's fields with auth
// and transport redacted.
func redactConnectorFields(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k == "auth" || k == "transport" {
			v = connector.RedactConfig(v)
		}
		out[k] = v
	}
	return out
}

// noun is the kind in words, for the operation summaries.
func (k revisionKind) noun() string {
	switch k.kind {
	case governance.KindDLPPolicy:
		return "data-loss prevention policy"
	case governance.KindApprovalPolicy:
		return "approval policy"
	case governance.KindIdentityProvider:
		return "identity provider"
	case governance.KindSAMLProvider:
		return "SAML provider"
	}
	return string(k.kind)
}

func revisionToDTO(r governance.Revision) revisionDTO {
	return revisionDTO{ID: r.ID, Kind: string(r.Kind), EntityID: r.EntityID, Revision: r.Number,
		Action: r.Action, ActorID: r.ActorID, ActorDisplay: r.ActorDisplay, CreatedAt: r.CreatedAt, Diff: r.Diff}
}

func (d Deps) revisionRoutes(api huma.API) {
	for _, k := range revisionKinds {
		d.revisionListRoute(api, k)
		d.revisionGetRoute(api, k)
	}
	d.connectorRestoreRoute(api)
	d.toolRestoreRoute(api)
	d.serverRestoreRoute(api)
	d.roleRestoreRoute(api)
}

func (d Deps) revisionListRoute(api huma.API, k revisionKind) {
	huma.Register(api, huma.Operation{OperationID: k.op + "-revisions-list", Method: http.MethodGet,
		Path: "/api/v1/" + k.path + "/{id}/revisions", Summary: "List the revisions of one " + k.noun(),
		Tags: []string{k.tag}, Security: sessionSecurity},
		func(ctx context.Context, in *revisionListInput) (*revisionListOutput, error) {
			p, err := d.require(ctx, k.read, k.resource(in.ID))
			if err != nil {
				return nil, err
			}
			if d.Revisions == nil {
				return nil, huma.Error503ServiceUnavailable("the revision history is not configured")
			}
			list, err := d.Revisions.List(ctx, p.OrgID, k.kind, in.ID, in.Before, in.Limit)
			if err != nil {
				return nil, err
			}
			out := &revisionListOutput{}
			out.Body.Revisions = make([]revisionDTO, 0, len(list))
			for _, r := range list {
				out.Body.Revisions = append(out.Body.Revisions, k.redact(revisionToDTO(r)))
			}
			// Only a full page can have anything behind it; a short one is
			// the start of the history, and saying so saves a round trip.
			if in.Limit > 0 && len(list) == in.Limit {
				out.Body.NextBefore = list[len(list)-1].Number
			}
			return out, nil
		})
}

func (d Deps) revisionGetRoute(api huma.API, k revisionKind) {
	huma.Register(api, huma.Operation{OperationID: k.op + "-revisions-get", Method: http.MethodGet,
		Path: "/api/v1/" + k.path + "/{id}/revisions/{revision}", Summary: "Read one revision of a " + k.noun(),
		Tags: []string{k.tag}, Security: sessionSecurity},
		func(ctx context.Context, in *revisionGetInput) (*struct{ Body revisionDTO }, error) {
			p, err := d.require(ctx, k.read, k.resource(in.ID))
			if err != nil {
				return nil, err
			}
			if d.Revisions == nil {
				return nil, huma.Error503ServiceUnavailable("the revision history is not configured")
			}
			r, err := d.Revisions.Get(ctx, p.OrgID, k.kind, in.ID, in.Revision)
			if err != nil {
				return nil, revisionErr(err)
			}
			fields, err := r.Fields()
			if err != nil {
				return nil, err
			}
			dto := revisionToDTO(*r)
			dto.Snapshot = fields
			return &struct{ Body revisionDTO }{Body: k.redact(dto)}, nil
		})
}

func (d Deps) connectorRestoreRoute(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "connectors-revisions-restore", Method: http.MethodPost,
		Path:        "/api/v1/connectors/{id}/revisions/{revision}/restore",
		Summary:     "Put a connector back the way an earlier revision found it",
		Description: "A browser session must have signed in within the fresh-auth window.", Tags: []string{"connectors"},
		Security: sessionSecurity},
		func(ctx context.Context, restore *versionedRestoreInput) (*struct{ Body connectorDTO }, error) {
			in := restore.revision()
			p, snapshot, err := d.snapshotToRestore(ctx, connectorRevisions, in)
			if err != nil {
				return nil, err
			}
			update := connector.UpdateInput{
				Name:         snapString(snapshot, "name"),
				Instructions: snapString(snapshot, "instructions"),
				ReadOnly:     snapBool(snapshot, "readOnly"),
				Enabled:      snapBool(snapshot, "enabled"),
				// The check is made under the row lock in the service, not
				// here: a restore is the write most likely to race.
				ExpectedVersion: restore.expectedVersion(),
			}
			var transport adapter.Transport
			if err := snapInto(snapshot, "transport", &transport); err != nil {
				return nil, err
			}
			var auth adapter.Auth
			if err := snapInto(snapshot, "auth", &auth); err != nil {
				return nil, err
			}
			update.Transport, update.Auth = &transport, &auth

			c, err := d.Connectors.Update(ctx, p.OrgID, in.ID, update)
			if err != nil {
				d.restoreFailed(ctx, connectorRevisions, in, err)
				return nil, humaErr(err)
			}
			d.restored(ctx, connectorRevisions, in, c.Name)
			return &struct{ Body connectorDTO }{Body: d.connectorDTO(c)}, nil
		})
}

func (d Deps) serverRestoreRoute(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "servers-revisions-restore", Method: http.MethodPost,
		Path:        "/api/v1/servers/{id}/revisions/{revision}/restore",
		Summary:     "Put an MCP server back the way an earlier revision found it",
		Description: "A browser session must have signed in within the fresh-auth window.", Tags: []string{"servers"},
		Security: sessionSecurity},
		func(ctx context.Context, restore *versionedRestoreInput) (*struct{ Body *mcpserver.Server }, error) {
			in := restore.revision()
			p, snapshot, err := d.snapshotToRestore(ctx, serverRevisions, in)
			if err != nil {
				return nil, err
			}
			srv, err := d.Servers.Update(ctx, p.OrgID, in.ID, mcpserver.UpdateInput{
				Name:            snapString(snapshot, "name"),
				Instructions:    snapString(snapshot, "instructions"),
				Enabled:         snapBool(snapshot, "enabled"),
				ConnectorIDs:    snapStrings(snapshot, "connectorIds"),
				ExpectedVersion: restore.expectedVersion(),
			})
			if err != nil {
				d.restoreFailed(ctx, serverRevisions, in, err)
				return nil, humaErr(err)
			}
			d.restored(ctx, serverRevisions, in, srv.Name)
			return &struct{ Body *mcpserver.Server }{Body: srv}, nil
		})
}

// A tool restores its name and definition through the same path as an
// edit, with the same escalations: a restore that changes what a call
// does needs connectors:update, and one that takes the destructive hint
// off needs tools:invoke:destructive. A restore that renames the tool
// past name-matched approval policies is refused like an edit is, unless
// the caller acknowledges them.
//
// Revisions written before definitions were recorded carry only whether
// the tool was enabled, so that is all they put back. A deleted tool
// cannot be restored from its history.
func (d Deps) toolRestoreRoute(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "tools-revisions-restore", Method: http.MethodPost,
		Path:    "/api/v1/tools/{id}/revisions/{revision}/restore",
		Summary: "Put a tool back the way an earlier revision found it", Tags: []string{"connectors"},
		Security: sessionSecurity},
		func(ctx context.Context, restore *toolRestoreInput) (*struct{ Body toolDTO }, error) {
			in := &revisionGetInput{ID: restore.ID, Revision: restore.Revision}
			if d.Revisions == nil {
				return nil, huma.Error503ServiceUnavailable("the revision history is not configured")
			}
			p, current, err := d.requireTool(ctx, authz.RevisionsRollback, in.ID)
			var status huma.StatusError
			if errors.As(err, &status) && status.GetStatus() == http.StatusNotFound {
				// The caller passed the permission check on the tool id, so
				// saying whether it has a history leaks nothing.
				caller, _ := authz.From(ctx)
				if _, serr := d.Revisions.Snapshot(ctx, caller.OrgID, toolRevisions.kind, in.ID, in.Revision); serr != nil {
					return nil, revisionErr(serr)
				}
				return nil, huma.Error404NotFound("this tool has been deleted; a deleted tool cannot be restored from its history")
			}
			if err != nil {
				return nil, err
			}
			snapshot, err := d.Revisions.Snapshot(ctx, p.OrgID, toolRevisions.kind, in.ID, in.Revision)
			if err != nil {
				return nil, revisionErr(err)
			}
			if connectorID, _ := snapshot["connectorId"].(string); connectorID != "" && connectorID != current.ConnectorID {
				return nil, huma.Error422UnprocessableEntity("this revision belongs to a different connector")
			}
			enabled, _ := snapshot["enabled"].(bool)

			t := current
			if raw, ok := snapshot["definition"].(string); ok {
				def, err := connector.ParseToolJSON([]byte(raw))
				if err != nil {
					return nil, huma.Error422UnprocessableEntity("this revision's definition cannot be read back")
				}
				u, err := d.updateTool(ctx, p, current, connector.ToolInput{
					Definition: def, Enabled: &enabled, ExpectedVersion: current.Version,
					AcknowledgeReferences: restore.AcknowledgeReferences, ActorID: p.ID,
				})
				if err != nil {
					d.restoreFailed(ctx, toolRevisions, in, err)
					return nil, err
				}
				t = u.tool
				d.toolChanged(ctx, "tool.update", t, audit.Changes(toolAudit(current), toolAudit(t)), u.declassified)
			} else {
				if err := d.Connectors.SetToolEnabled(ctx, p.OrgID, in.ID, enabled, p.ID); err != nil {
					d.restoreFailed(ctx, toolRevisions, in, err)
					return nil, humaErr(err)
				}
				if t, err = d.Connectors.GetTool(ctx, p.OrgID, in.ID); err != nil {
					return nil, humaErr(err)
				}
			}
			c, err := d.Connectors.Get(ctx, p.OrgID, t.ConnectorID)
			if err != nil {
				return nil, humaErr(err)
			}
			d.restored(ctx, toolRevisions, in, t.Name)
			return &struct{ Body toolDTO }{Body: toolToDTO(t, c)}, nil
		})
}

// versionedRestoreInput is a connector or server restore. The body is
// optional, as expectedVersion is for one release; a restore sent without
// one is not checked against a version.
type versionedRestoreInput struct {
	ID       string `path:"id"`
	Revision int    `path:"revision" minimum:"1"`
	Body     *struct {
		ExpectedVersion int64 `json:"expectedVersion,omitempty" minimum:"0" doc:"The version that was read. A mismatch is a 409. Optional for now; a later release requires it"`
	}
}

func (in *versionedRestoreInput) revision() *revisionGetInput {
	return &revisionGetInput{ID: in.ID, Revision: in.Revision}
}

func (in *versionedRestoreInput) expectedVersion() int64 {
	if in.Body == nil {
		return 0
	}
	return in.Body.ExpectedVersion
}

type toolRestoreInput struct {
	ID                    string `path:"id"`
	Revision              int    `path:"revision" minimum:"1"`
	AcknowledgeReferences bool   `query:"acknowledgeReferences" doc:"Restore an earlier name even though approval policies match the tool by its current name"`
}

// A role's whole definition is its name, the sentence about it and what
// it allows, so a role restores wholesale, through the same handler an
// edit goes through: the built-in roles are refused there too.
func (d Deps) roleRestoreRoute(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "roles-revisions-restore", Method: http.MethodPost,
		Path:        "/api/v1/roles/{id}/revisions/{revision}/restore",
		Summary:     "Put a role back the way an earlier revision found it",
		Description: "A browser session must have signed in within the fresh-auth window.", Tags: []string{"roles"},
		Security: sessionSecurity},
		func(ctx context.Context, in *revisionGetInput) (*struct{ Body roleDTO }, error) {
			// Restoring a role changes what it allows, like an edit does;
			// snapshotToRestore has asked for a recent sign-in.
			p, snapshot, err := d.snapshotToRestore(ctx, roleRevisions, in)
			if err != nil {
				return nil, err
			}
			role, before, err := d.updateRole(ctx, p, in.ID, roleWriteBody{
				Name:        *snapString(snapshot, "name"),
				Description: *snapString(snapshot, "description"),
				Permissions: *snapStrings(snapshot, "permissions"),
			})
			if err != nil {
				d.restoreFailed(ctx, roleRevisions, in, err)
				return nil, roleErr(err)
			}
			d.admin(ctx, "role.update", "role", role.ID, role.Name, audit.Changes(before, role))
			d.forgetRoles(p.OrgID)
			d.restored(ctx, roleRevisions, in, role.Name)
			return &struct{ Body roleDTO }{Body: role}, nil
		})
}

// snapshotToRestore authorises the rollback and reads the snapshot to put
// back. It deliberately does not apply anything: each kind has its own
// owning service, and that service decides what a restore means.
//
// A restore can put back connectors a server served, or a connector's
// upstream and how it signs in, so it asks a browser session for a recent
// sign-in, before the snapshot is read.
func (d Deps) snapshotToRestore(ctx context.Context, k revisionKind, in *revisionGetInput) (*authz.Principal, map[string]any, error) {
	p, err := d.requireFresh(ctx, authz.RevisionsRollback, k.resource(in.ID))
	if err != nil {
		return nil, nil, err
	}
	if k.edit != "" {
		if _, err := d.require(ctx, k.edit, k.resource(in.ID)); err != nil {
			return nil, nil, err
		}
	}
	if d.Revisions == nil {
		return nil, nil, huma.Error503ServiceUnavailable("the revision history is not configured")
	}
	snapshot, err := d.Revisions.Snapshot(ctx, p.OrgID, k.kind, in.ID, in.Revision)
	if err != nil {
		return nil, nil, revisionErr(err)
	}
	return p, snapshot, nil
}

// restored records the rollback. The new state is recorded by the owning
// service as an ordinary update; what only this handler knows is which
// revision the caller asked to go back to.
func (d Deps) restored(ctx context.Context, k revisionKind, in *revisionGetInput, display string) {
	d.emit(ctx, audit.Event{Category: audit.CategoryGovernan, Action: string(k.kind) + ".revision.restore",
		Outcome: audit.Success, TargetKind: string(k.kind), TargetID: in.ID, TargetDisplay: display,
		Meta: map[string]any{"revision": in.Revision}})
}

func (d Deps) restoreFailed(ctx context.Context, k revisionKind, in *revisionGetInput, err error) {
	d.emit(ctx, audit.Event{Category: audit.CategoryGovernan, Action: string(k.kind) + ".revision.restore",
		Outcome: audit.Failure, TargetKind: string(k.kind), TargetID: in.ID,
		Meta: errorMeta(ctx, map[string]any{"revision": in.Revision}, "error", err)})
}

func revisionErr(err error) error {
	if errors.Is(err, governance.ErrNotFound) {
		return huma.Error404NotFound(err.Error())
	}
	return err
}

// A snapshot is the whole entity, so a field it does not mention was empty
// when it was taken. Restoring has to put that emptiness back rather than
// leave today's value in place, which is why these always return a value.

func snapString(m map[string]any, key string) *string {
	s, _ := m[key].(string)
	return &s
}

func snapBool(m map[string]any, key string) *bool {
	b, _ := m[key].(bool)
	return &b
}

func snapStrings(m map[string]any, key string) *[]string {
	list, _ := m[key].([]any)
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return &out
}

// snapInto re-reads a nested part of the snapshot as the type that owns
// it, so a restore puts back a transport or an auth block the service can
// use rather than a bag of values. An empty key reads the whole snapshot.
func snapInto(m map[string]any, key string, dst any) error {
	var v any = m
	what := "snapshot"
	if key != "" {
		v, what = m[key], key
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return huma.Error422UnprocessableEntity("this revision's " + what + " cannot be read back")
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return huma.Error422UnprocessableEntity("this revision's " + what + " cannot be read back")
	}
	return nil
}
