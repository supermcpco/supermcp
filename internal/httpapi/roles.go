package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/governance"
	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// --- roles -----------------------------------------------------------------

// The permission set is closed and the built-in roles arrive with a
// migration; what an administrator adds here is a role of their own,
// built out of that same set, and who holds it.
//
// Everything a caller sends is checked against the organisation before it
// is stored: a principal id and a scope id are just strings on the wire,
// and a binding that names something in another tenant would be a quiet
// way to widen access.
//
// A built-in role is never edited. It is the same in every organisation,
// and a workspace that had quietly redefined "reader" would be a
// workspace nobody could reason about from the outside.

// ownerRoleID is the built-in role that can do anything, seeded by
// 00002_domain.sql. It is named here so the last owner cannot be revoked.
const ownerRoleID = "role_owner"

// roleDTO is a role as a screen shows it.
type roleDTO struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	BuiltIn     bool     `json:"builtIn" doc:"Shipped with the product and the same in every organisation"`
	Permissions []string `json:"permissions" nullable:"false"`
	Holders     int      `json:"holders" doc:"How many people and service accounts hold this role"`
}

// permissionDTO pairs a permission with a sentence a reader outside the
// team can act on.
type permissionDTO struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

type permissionGroupDTO struct {
	Resource    string          `json:"resource"`
	Title       string          `json:"title"`
	Permissions []permissionDTO `json:"permissions" nullable:"false"`
}

// bindingDTO is one grant of a role: who holds it, over what, and how they
// came to hold it.
type bindingDTO struct {
	ID            string     `json:"id"`
	PrincipalKind string     `json:"principalKind" enum:"user,service_account,idp_group"`
	PrincipalID   string     `json:"principalId"`
	Display       string     `json:"display,omitempty" doc:"The person, service account or group by name, where we have one"`
	ScopeKind     string     `json:"scopeKind" enum:"org,server,connector,tool"`
	ScopeID       string     `json:"scopeId,omitempty"`
	ScopeDisplay  string     `json:"scopeDisplay,omitempty"`
	Source        string     `json:"source" doc:"manual when someone granted it here, sso when an identity provider did"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
}

type rolesOutput struct {
	Body struct {
		Roles []roleDTO `json:"roles" nullable:"false"`
	}
}

type permissionsOutput struct {
	Body struct {
		Groups []permissionGroupDTO `json:"groups" nullable:"false"`
	}
}

type bindingsOutput struct {
	Body struct {
		Bindings []bindingDTO `json:"bindings" nullable:"false"`
	}
}

type bindingOutput struct {
	Body bindingDTO
}

type createBindingInput struct {
	ID   string `path:"id"`
	Body struct {
		PrincipalKind string `json:"principalKind" enum:"user,service_account,idp_group"`
		PrincipalID   string `json:"principalId" minLength:"1"`
		ScopeKind     string `json:"scopeKind,omitempty" enum:"org,server,connector,tool" default:"org"`
		ScopeID       string `json:"scopeId,omitempty" doc:"The server, connector or tool the role applies to; leave empty for the whole organisation"`
	}
}

type deleteBindingInput struct {
	ID        string `path:"id"`
	BindingID string `path:"bindingId"`
}

// roleWriteBody is a custom role as somebody builds it. The permissions
// are checked against the closed set before anything is stored, so a
// typo cannot become a role that grants nothing and looks like it does.
type roleWriteBody struct {
	Name        string   `json:"name" minLength:"1" maxLength:"64"`
	Description string   `json:"description,omitempty" maxLength:"280" doc:"One sentence about who this role is for"`
	Permissions []string `json:"permissions" nullable:"false" minItems:"1"`
}

type createRoleInput struct {
	Body roleWriteBody
}

type updateRoleInput struct {
	ID   string `path:"id"`
	Body roleWriteBody
}

type roleOutput struct {
	Body roleDTO
}

// --- the effective-permission preview ---------------------------------------

// A permission list is not an answer to "what could somebody holding this
// actually do?". The answer depends on the other roles that person holds
// and on the tool rules that take things away again, so the preview is
// worked out on the server, by the same evaluator that decides a real
// request. Anything else would be a second set of rules to keep in step.

type previewInput struct {
	Body struct {
		Permissions   []string `json:"permissions" nullable:"false" doc:"The permission set being built"`
		RoleID        string   `json:"roleId,omitempty" doc:"The role being edited, where there is one already"`
		PrincipalKind string   `json:"principalKind,omitempty" enum:"user,service_account"`
		PrincipalID   string   `json:"principalId,omitempty" doc:"Somebody who would hold this role, so the preview counts what their other roles already allow"`
	}
}

// allowDTO is one thing a holder could do, and where that comes from.
type allowDTO struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	FromThis    bool     `json:"fromThis" doc:"The set being built allows it"`
	FromOther   []string `json:"fromOther" nullable:"false" doc:"Other roles the holder has that already allow it"`
}

// restrictionDTO is a tool rule that changes the answer for one tool,
// either by keeping a role away from it or by limiting it to a few.
type restrictionDTO struct {
	ToolID   string `json:"toolId"`
	ToolName string `json:"toolName"`
	Allowed  bool   `json:"allowed"`
	Detail   string `json:"detail"`
}

type previewOutput struct {
	Body struct {
		Allows       []allowDTO       `json:"allows" nullable:"false"`
		Restrictions []restrictionDTO `json:"restrictions" nullable:"false"`
		Holder       string           `json:"holder,omitempty" doc:"The person or service account the preview was worked out for"`
		OtherRoles   []string         `json:"otherRoles" nullable:"false" doc:"The roles that holder already has"`
		Unknown      []string         `json:"unknown" nullable:"false" doc:"Entries in the set that are not permissions this build knows"`
	}
}

// roleRoutes serve the roles screen: what the roles are, what each
// permission actually allows, and who holds what.
func (d Deps) roleRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "list-roles", Method: http.MethodGet,
		Path: "/api/v1/roles", Summary: "List the roles and how many people hold each",
		Tags: []string{"roles"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*rolesOutput, error) {
			p, err := d.require(ctx, authz.RolesRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			roles, err := d.listRoles(ctx, p.OrgID)
			if err != nil {
				return nil, err
			}
			out := &rolesOutput{}
			out.Body.Roles = roles
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "list-permissions", Method: http.MethodGet,
		Path: "/api/v1/permissions", Summary: "Describe what each permission allows",
		Tags: []string{"roles"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*permissionsOutput, error) {
			if _, err := d.require(ctx, authz.RolesRead, authz.Resource{}); err != nil {
				return nil, err
			}
			out := &permissionsOutput{}
			out.Body.Groups = permissionCatalogue()
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "create-role", Method: http.MethodPost,
		Path: "/api/v1/roles", Summary: "Create a role of your own",
		Tags: []string{"roles"}, Security: sessionSecurity, DefaultStatus: http.StatusCreated},
		func(ctx context.Context, in *createRoleInput) (*roleOutput, error) {
			p, err := d.require(ctx, authz.RolesManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			role, err := d.createRole(ctx, p, in.Body)
			if err != nil {
				d.adminFailed(ctx, "role.create", "role", "", err)
				return nil, roleErr(err)
			}
			d.admin(ctx, "role.create", "role", role.ID, role.Name, audit.Created(role))
			d.forgetRoles(p.OrgID)
			return &roleOutput{Body: role}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "update-role", Method: http.MethodPatch,
		Path: "/api/v1/roles/{id}", Summary: "Change what a role allows",
		Tags: []string{"roles"}, Security: sessionSecurity},
		func(ctx context.Context, in *updateRoleInput) (*roleOutput, error) {
			p, err := d.require(ctx, authz.RolesManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			role, before, err := d.updateRole(ctx, p, in.ID, in.Body)
			if err != nil {
				d.adminFailed(ctx, "role.update", "role", in.ID, err)
				return nil, roleErr(err)
			}
			d.admin(ctx, "role.update", "role", role.ID, role.Name, audit.Changes(before, role))
			d.forgetRoles(p.OrgID)
			return &roleOutput{Body: role}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "delete-role", Method: http.MethodDelete,
		Path: "/api/v1/roles/{id}", Summary: "Delete a role of your own",
		Tags: []string{"roles"}, Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct{}, error) {
			p, err := d.require(ctx, authz.RolesManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			role, err := d.deleteRole(ctx, p, in.ID)
			if err != nil {
				d.adminFailed(ctx, "role.delete", "role", in.ID, err)
				return nil, roleErr(err)
			}
			d.admin(ctx, "role.delete", "role", role.ID, role.Name, audit.Deleted(role))
			d.forgetRoles(p.OrgID)
			return nil, nil //nolint:nilnil // huma's no-content shape
		})

	huma.Register(api, huma.Operation{OperationID: "preview-role", Method: http.MethodPost,
		Path: "/api/v1/roles/preview", Summary: "Work out what somebody holding a permission set could do",
		Tags: []string{"roles"}, Security: sessionSecurity},
		func(ctx context.Context, in *previewInput) (*previewOutput, error) {
			p, err := d.require(ctx, authz.RolesRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			out, err := d.previewRole(ctx, p, in)
			if err != nil {
				return nil, roleErr(err)
			}
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "list-role-bindings", Method: http.MethodGet,
		Path: "/api/v1/roles/{id}/bindings", Summary: "List who holds a role",
		Tags: []string{"roles"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*bindingsOutput, error) {
			p, err := d.require(ctx, authz.RolesRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			bindings, err := d.listBindings(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, humaErr(err)
			}
			out := &bindingsOutput{}
			out.Body.Bindings = bindings
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "create-role-binding", Method: http.MethodPost,
		Path: "/api/v1/roles/{id}/bindings", Summary: "Give someone a role",
		Tags: []string{"roles"}, Security: sessionSecurity, DefaultStatus: http.StatusCreated},
		func(ctx context.Context, in *createBindingInput) (*bindingOutput, error) {
			p, err := d.require(ctx, authz.RolesManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			b, roleName, err := d.createBinding(ctx, p, in)
			if err != nil {
				d.adminFailed(ctx, "role.binding.create", "role_binding", "", err)
				return nil, bindingErr(err)
			}
			d.admin(ctx, "role.binding.create", "role_binding", b.ID, roleName+" for "+holderName(b),
				audit.Created(b))
			// The evaluator caches bindings for half a minute, and a grant
			// nobody can use yet looks like a bug to the person who made it.
			d.invalidate(p.OrgID, b.PrincipalKind, b.PrincipalID)
			return &bindingOutput{Body: b}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "delete-role-binding", Method: http.MethodDelete,
		Path: "/api/v1/roles/{id}/bindings/{bindingId}", Summary: "Take a role away from someone",
		Tags: []string{"roles"}, Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *deleteBindingInput) (*struct{}, error) {
			p, err := d.require(ctx, authz.RolesManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			b, roleName, err := d.deleteBinding(ctx, p.OrgID, in.ID, in.BindingID)
			if err != nil {
				d.adminFailed(ctx, "role.binding.delete", "role_binding", in.BindingID, err)
				return nil, bindingErr(err)
			}
			d.admin(ctx, "role.binding.delete", "role_binding", b.ID, roleName+" for "+holderName(b),
				audit.Deleted(b))
			d.invalidate(p.OrgID, b.PrincipalKind, b.PrincipalID)
			return nil, nil //nolint:nilnil // huma's no-content shape
		})
}

// --- storage ---------------------------------------------------------------

// listRoles reads every role the organisation can use. Row-level security
// already limits this to the built-in roles plus the organisation's own,
// and the holder count to bindings made in this organisation.
func (d Deps) listRoles(ctx context.Context, orgID string) ([]roleDTO, error) {
	out := []roleDTO{}
	err := d.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT r.id, r.name, r.description, r.is_system, r.permissions,
       (SELECT count(DISTINCT (b.principal_kind, b.principal_id))
          FROM role_bindings b WHERE b.role_id = r.id)
FROM roles r
ORDER BY r.is_system DESC, r.name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r roleDTO
			var holders int64
			if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.BuiltIn, &r.Permissions, &holders); err != nil {
				return err
			}
			r.Holders = int(holders)
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("read roles: %w", err)
	}
	return out, nil
}

// roleSelect reads one role the same way the list does, so a role that
// has just been written comes back looking like the ones beside it.
const roleSelect = `
SELECT r.id, r.name, r.description, r.is_system, r.permissions,
       (SELECT count(DISTINCT (b.principal_kind, b.principal_id))
          FROM role_bindings b WHERE b.role_id = r.id)
FROM roles r WHERE r.id = $1`

func scanRole(row pgx.Row) (roleDTO, error) {
	var r roleDTO
	var holders int64
	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.BuiltIn, &r.Permissions, &holders)
	r.Holders = int(holders)
	return r, err
}

// lockRole takes the role's row lock. It is its own statement because
// the read beside it counts holders, and a lock cannot be taken through
// an aggregate.
func lockRole(ctx context.Context, tx pgx.Tx, id string) error {
	var one int
	err := tx.QueryRow(ctx, `SELECT 1 FROM roles WHERE id = $1 FOR UPDATE`, id).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return errNoSuchRole
	}
	return err
}

func readRole(ctx context.Context, tx pgx.Tx, id string) (roleDTO, error) {
	r, err := scanRole(tx.QueryRow(ctx, roleSelect, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return roleDTO{}, errNoSuchRole
	}
	return r, err
}

// createRole writes a role and its first revision together. A role whose
// history begins after the fact cannot show what it looked like when
// somebody was first given it, which is the version most worth seeing.
func (d Deps) createRole(ctx context.Context, p *authz.Principal, body roleWriteBody) (roleDTO, error) {
	draft, err := cleanRole(body)
	if err != nil {
		return roleDTO{}, err
	}
	draft.ID = newRoleID()
	var out roleDTO
	err = d.DB.Tx(tenant.WithOrg(ctx, p.OrgID), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
INSERT INTO roles (id, organization_id, name, description, is_system, permissions)
VALUES ($1, $2, $3, $4, false, $5)`,
			draft.ID, p.OrgID, draft.Name, draft.Description, draft.Permissions); err != nil {
			return err
		}
		if out, err = readRole(ctx, tx, draft.ID); err != nil {
			return err
		}
		return d.recordRole(ctx, tx, out, governance.ActionCreate, audit.Created(out), p.ID)
	})
	if err != nil {
		return roleDTO{}, err
	}
	return out, nil
}

// updateRole replaces what a role allows, and hands back what it allowed
// before so the audit record and the revision both say what changed.
func (d Deps) updateRole(ctx context.Context, p *authz.Principal, id string, body roleWriteBody) (roleDTO, roleDTO, error) {
	draft, err := cleanRole(body)
	if err != nil {
		return roleDTO{}, roleDTO{}, err
	}
	var before, after roleDTO
	err = d.DB.Tx(tenant.WithOrg(ctx, p.OrgID), func(tx pgx.Tx) error {
		// The row is locked before it is read, so two administrators
		// editing the same role queue rather than one of them writing a
		// permission set worked out from what the other has replaced.
		if err := lockRole(ctx, tx, id); err != nil {
			return err
		}
		if before, err = readRole(ctx, tx, id); err != nil {
			return err
		}
		if before.BuiltIn {
			return errBuiltInRole
		}
		if _, err := tx.Exec(ctx, `
UPDATE roles SET name = $2, description = $3, permissions = $4, revision = revision + 1, updated_at = now()
WHERE id = $1`, id, draft.Name, draft.Description, draft.Permissions); err != nil {
			return err
		}
		if after, err = readRole(ctx, tx, id); err != nil {
			return err
		}
		return d.recordRole(ctx, tx, after, governance.ActionUpdate, audit.Changes(before, after), p.ID)
	})
	if err != nil {
		return roleDTO{}, roleDTO{}, err
	}
	return after, before, nil
}

// deleteRole removes a role nobody holds. A role that is still held is
// refused rather than cascaded away: the holders would lose access in
// silence, and the screen can say so instead.
func (d Deps) deleteRole(ctx context.Context, p *authz.Principal, id string) (roleDTO, error) {
	var role roleDTO
	err := d.DB.Tx(tenant.WithOrg(ctx, p.OrgID), func(tx pgx.Tx) error {
		var err error
		// Locking the row first is what makes the holder count below mean
		// something: without it somebody could be given the role between
		// the count and the delete, and lose it again without being told.
		if err := lockRole(ctx, tx, id); err != nil {
			return err
		}
		if role, err = readRole(ctx, tx, id); err != nil {
			return err
		}
		if role.BuiltIn {
			return errBuiltInRole
		}
		if role.Holders > 0 {
			return errRoleHeld
		}
		if _, err := tx.Exec(ctx, `DELETE FROM roles WHERE id = $1`, id); err != nil {
			return err
		}
		return d.recordRole(ctx, tx, role, governance.ActionDelete, audit.Deleted(role), p.ID)
	})
	if err != nil {
		return roleDTO{}, err
	}
	return role, nil
}

// recordRole writes the role's history inside the transaction that
// changed it, the way a connector's is written: a history that can be
// lost separately from the change it describes looks complete when it is
// not.
//
// The history keeps a closed set of entity kinds. Where a deployment's
// history does not yet keep roles it refuses the row, and that refusal is
// contained here so it takes the revision rather than the change with it:
// an administrator who cannot edit a role at all is a worse failure than
// a role whose history starts once the history knows about roles. Every
// other failure is a failure of the change.
func (d Deps) recordRole(ctx context.Context, tx pgx.Tx, role roleDTO, action string, diff *audit.Diff, actorID string) error {
	if d.Revisions == nil {
		return nil
	}
	nested, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	if err := d.Revisions.Record(ctx, nested, string(governance.KindRole), role.ID, action, role, diff, actorID); err != nil {
		_ = nested.Rollback(ctx)
		if historyKeepsNoRoles(err) {
			return nil
		}
		return err
	}
	return nested.Commit(ctx)
}

// historyKeepsNoRoles reports the one refusal that is about the
// deployment rather than about the change: a history whose entity kinds
// do not include a role, either in the service's own set or in the
// constraint behind it.
func historyKeepsNoRoles(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// 23514 is a check constraint; the one that matters names the
		// column whose values the history is closed over.
		return pgErr.Code == "23514" && strings.Contains(pgErr.ConstraintName, "entity_kind")
	}
	return strings.Contains(err.Error(), "unknown entity kind")
}

// cleanRole normalises what a caller sent and refuses what cannot become
// a role: no name, nothing it allows, or a permission this build has
// never heard of.
func cleanRole(body roleWriteBody) (roleDTO, error) {
	name := strings.TrimSpace(body.Name)
	if name == "" {
		return roleDTO{}, errRoleNameNeeded
	}
	permissions, unknown := splitPermissions(body.Permissions)
	if len(unknown) > 0 {
		return roleDTO{}, fmt.Errorf("%w: %s", errNoSuchPermission, strings.Join(unknown, ", "))
	}
	if len(permissions) == 0 {
		return roleDTO{}, errRoleAllowsNothing
	}
	return roleDTO{Name: name, Description: strings.TrimSpace(body.Description), Permissions: permissions}, nil
}

// splitPermissions sorts the wheat from the chaff, de-duplicating as it
// goes so a set built by clicking twice is the same set as one built by
// clicking once.
func splitPermissions(in []string) (known, unknown []string) {
	seen := map[string]bool{}
	known, unknown = []string{}, []string{}
	for _, raw := range in {
		p := strings.TrimSpace(raw)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		if authz.Valid(authz.Permission(p)) {
			known = append(known, p)
			continue
		}
		unknown = append(unknown, p)
	}
	sort.Strings(known)
	return known, unknown
}

// forgetRoles drops every cached decision in the organisation. A role's
// permissions are shared by everyone holding it, so unlike a single
// grant there is no one principal whose cache to drop.
func (d Deps) forgetRoles(orgID string) {
	if d.Authz == nil {
		return
	}
	d.Authz.Invalidate(orgID, "", "")
}

// bindingSelect is shared by the list and the single-row reads so the
// display names are resolved the same way everywhere. A principal who has
// since left the organisation resolves to no name rather than no row.
const bindingSelect = `
SELECT b.id, b.principal_kind, b.principal_id,
       COALESCE(NULLIF(u.name, ''), u.email, sa.name, g.display_name, ''),
       b.scope_kind, COALESCE(b.scope_id, ''),
       COALESCE(srv.name, con.name, tl.name, ''),
       b.source, b.expires_at, b.created_at
FROM role_bindings b
LEFT JOIN users u             ON b.principal_kind = 'user'            AND u.id = b.principal_id
LEFT JOIN service_accounts sa ON b.principal_kind = 'service_account' AND sa.id = b.principal_id
LEFT JOIN scim_groups g       ON b.principal_kind = 'idp_group'       AND g.id = b.principal_id
LEFT JOIN mcp_servers srv     ON b.scope_kind = 'server'    AND srv.id = b.scope_id
LEFT JOIN connectors con      ON b.scope_kind = 'connector' AND con.id = b.scope_id
LEFT JOIN tools tl            ON b.scope_kind = 'tool'      AND tl.id = b.scope_id`

func scanBinding(row pgx.Row) (bindingDTO, error) {
	var b bindingDTO
	err := row.Scan(&b.ID, &b.PrincipalKind, &b.PrincipalID, &b.Display,
		&b.ScopeKind, &b.ScopeID, &b.ScopeDisplay, &b.Source, &b.ExpiresAt, &b.CreatedAt)
	return b, err
}

func (d Deps) listBindings(ctx context.Context, orgID, roleID string) ([]bindingDTO, error) {
	out := []bindingDTO{}
	err := d.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		if _, err := roleName(ctx, tx, roleID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, bindingSelect+`
WHERE b.role_id = $1 ORDER BY b.created_at`, roleID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			b, err := scanBinding(rows)
			if err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// createBinding grants a role. Every id in the body is resolved against
// the organisation first; an id that resolves to nothing is refused rather
// than stored, because row-level security would let the row exist while
// the evaluator could never match it to anyone.
func (d Deps) createBinding(ctx context.Context, p *authz.Principal, in *createBindingInput) (bindingDTO, string, error) {
	var out bindingDTO
	var name string
	scopeKind := in.Body.ScopeKind
	if scopeKind == "" {
		scopeKind = "org"
	}
	err := d.DB.Tx(tenant.WithOrg(ctx, p.OrgID), func(tx pgx.Tx) error {
		var err error
		if name, err = roleName(ctx, tx, in.ID); err != nil {
			return err
		}
		if err := principalExists(ctx, tx, p.OrgID, in.Body.PrincipalKind, in.Body.PrincipalID); err != nil {
			return err
		}
		scopeID, err := checkScope(ctx, tx, p.OrgID, scopeKind, in.Body.ScopeID)
		if err != nil {
			return err
		}
		// The unique constraint covers scope_id, and Postgres treats NULLs
		// as distinct, so an organisation-wide duplicate would slip past it.
		var existing string
		err = tx.QueryRow(ctx, `
SELECT id FROM role_bindings
WHERE organization_id = $1 AND principal_kind = $2 AND principal_id = $3
  AND role_id = $4 AND scope_kind = $5 AND scope_id IS NOT DISTINCT FROM $6`,
			p.OrgID, in.Body.PrincipalKind, in.Body.PrincipalID, in.ID, scopeKind, scopeID).Scan(&existing)
		switch {
		case err == nil:
			return errAlreadyHeld
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		id := newBindingID()
		if _, err := tx.Exec(ctx, `
INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id, scope_kind, scope_id, source, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'manual', $8)`,
			id, p.OrgID, in.Body.PrincipalKind, in.Body.PrincipalID, in.ID, scopeKind, scopeID, p.ID); err != nil {
			return err
		}
		out, err = scanBinding(tx.QueryRow(ctx, bindingSelect+` WHERE b.id = $1`, id))
		return err
	})
	if err != nil {
		return bindingDTO{}, "", err
	}
	return out, name, nil
}

// deleteBinding revokes a role and returns what it revoked, so the audit
// record names a person rather than an identifier. Taking away an owner
// binding follows the members API's rule: under the organisation's row
// lock, and refused when it would leave no active owner.
func (d Deps) deleteBinding(ctx context.Context, orgID, roleID, bindingID string) (bindingDTO, string, error) {
	var out bindingDTO
	var name string
	err := d.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		if err := identity.LockOrganization(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if name, err = roleName(ctx, tx, roleID); err != nil {
			return err
		}
		out, err = scanBinding(tx.QueryRow(ctx, bindingSelect+` WHERE b.id = $1 AND b.role_id = $2`, bindingID, roleID))
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoSuchBinding
		}
		if err != nil {
			return err
		}
		remove := func() error {
			_, err := tx.Exec(ctx, `DELETE FROM role_bindings WHERE id = $1`, bindingID)
			return err
		}
		// Only a person's organisation-wide owner binding can make someone
		// an active owner; KeepOwner decides whether this one did.
		if roleID != ownerRoleID || out.PrincipalKind != "user" {
			return remove()
		}
		// Removing the last owner leaves nobody who can grant the role
		// back, and no support path short of editing the database.
		return identity.KeepOwner(ctx, tx, orgID, out.PrincipalID, remove)
	})
	if err != nil {
		return bindingDTO{}, "", err
	}
	return out, name, nil
}

// --- helpers ---------------------------------------------------------------

var (
	errNoSuchRole        = errors.New("no such role")
	errNoSuchBinding     = errors.New("no such role assignment")
	errNoSuchPrincipal   = errors.New("that person or service account is not in this organisation")
	errNoSuchScope       = errors.New("that server, connector or tool is not in this organisation")
	errScopeNeeded       = errors.New("a role limited to a server, connector or tool needs the id of one")
	errAlreadyHeld       = errors.New("they already hold this role here")
	errBuiltInRole       = errors.New("a built-in role is the same in every workspace and cannot be changed here")
	errRoleNameNeeded    = errors.New("a role needs a name")
	errRoleAllowsNothing = errors.New("a role has to allow at least one thing")
	errRoleHeld          = errors.New("somebody still holds this role; take it away from them first")
	errRoleNameTaken     = errors.New("a role with that name already exists")
	errNoSuchPermission  = errors.New("that is not something this workspace can allow")
)

// roleErr maps the refusals above onto status codes, including the two
// the database raises: a duplicate name and a role somebody still holds
// are both the caller asking for something the data will not take.
func roleErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return huma.Error409Conflict(errRoleNameTaken.Error())
	}
	switch {
	case errors.Is(err, errNoSuchRole):
		return huma.Error404NotFound(err.Error())
	case errors.Is(err, errRoleNameNeeded), errors.Is(err, errRoleAllowsNothing),
		errors.Is(err, errNoSuchPermission), errors.Is(err, errNoSuchPrincipal):
		return huma.Error400BadRequest(err.Error())
	case errors.Is(err, errBuiltInRole), errors.Is(err, errRoleHeld), errors.Is(err, errRoleNameTaken):
		return huma.Error409Conflict(err.Error())
	}
	return err
}

// bindingErr maps the refusals above onto status codes. Anything else is a
// database failure and becomes a 500 with its detail hidden.
func bindingErr(err error) error {
	switch {
	case errors.Is(err, errNoSuchRole), errors.Is(err, errNoSuchBinding):
		return huma.Error404NotFound(err.Error())
	case errors.Is(err, errNoSuchPrincipal), errors.Is(err, errNoSuchScope), errors.Is(err, errScopeNeeded):
		return huma.Error400BadRequest(err.Error())
	case errors.Is(err, errAlreadyHeld):
		return huma.Error409Conflict(err.Error())
	case errors.Is(err, identity.ErrLastOwner):
		// The same reply, code included, as the members API gives.
		return memberErr(err)
	}
	return err
}

// roleName resolves a role the organisation may use. Row-level security
// hides another tenant's roles, so a miss is a 404 either way.
func roleName(ctx context.Context, tx pgx.Tx, roleID string) (string, error) {
	var name string
	err := tx.QueryRow(ctx, `SELECT name FROM roles WHERE id = $1`, roleID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errNoSuchRole
	}
	return name, err
}

// principalExists refuses a principal the organisation does not have. The
// organisation_id predicate is redundant under row-level security and kept
// so the query is still correct if it is ever read outside a tenant
// transaction.
func principalExists(ctx context.Context, tx pgx.Tx, orgID, kind, id string) error {
	var q string
	switch kind {
	case "user":
		q = `SELECT 1 FROM organization_members
             WHERE user_id = $1 AND organization_id = $2 AND deactivated_at IS NULL`
	case "service_account":
		q = `SELECT 1 FROM service_accounts WHERE id = $1 AND organization_id = $2`
	case "idp_group":
		q = `SELECT 1 FROM scim_groups WHERE id = $1 AND organization_id = $2`
	default:
		return errNoSuchPrincipal
	}
	var one int
	err := tx.QueryRow(ctx, q, id, orgID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return errNoSuchPrincipal
	}
	return err
}

// checkScope resolves what a binding is limited to, and returns the value
// to store: NULL for the whole organisation, the verified id otherwise.
func checkScope(ctx context.Context, tx pgx.Tx, orgID, kind, id string) (*string, error) {
	var q string
	switch kind {
	case "org":
		return nil, nil
	case "server":
		q = `SELECT 1 FROM mcp_servers WHERE id = $1 AND organization_id = $2`
	case "connector":
		q = `SELECT 1 FROM connectors WHERE id = $1 AND organization_id = $2`
	case "tool":
		q = `SELECT 1 FROM tools WHERE id = $1 AND organization_id = $2`
	default:
		return nil, errNoSuchScope
	}
	if id == "" {
		return nil, errScopeNeeded
	}
	var one int
	err := tx.QueryRow(ctx, q, id, orgID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNoSuchScope
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// invalidate drops the evaluator's cached bindings so a grant or a
// revocation takes effect on the next request to this replica. Other
// replicas hear of it from the database, whose triggers notify them on
// commit (internal/invalidation). A group has no cache key of its own,
// because the evaluator keys on the person doing the asking.
func (d Deps) invalidate(orgID, kind, id string) {
	if d.Authz == nil {
		return
	}
	if kind == "idp_group" {
		d.Authz.Invalidate(orgID, "", "")
		return
	}
	d.Authz.Invalidate(orgID, kind, id)
}

func holderName(b bindingDTO) string {
	if b.Display != "" {
		return b.Display
	}
	return b.PrincipalID
}

// newBindingID mints an identifier. UUIDv7 keeps rows roughly time-ordered
// and matches every other id in the schema.
func newBindingID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}

// newRoleID carries the same role_ prefix the built-in roles use, so an
// id in an audit record reads as a role wherever it turns up.
func newRoleID() string { return "role_" + newBindingID() }

// --- working out the preview ------------------------------------------------

// heldRole is one role a principal already holds over the whole
// organisation. A role that applies only to one connector cannot widen
// what a new role gives somebody everywhere, so it is left out rather
// than overstated.
type heldRole struct {
	id    string
	name  string
	perms map[string]bool
}

// previewRole answers "what could somebody holding this actually do?".
//
// The draft set is the caller's; everything else is read back from the
// workspace, and the part that decides — whether a tool rule takes a tool
// away again — is put to the evaluator that decides a real request.
func (d Deps) previewRole(ctx context.Context, p *authz.Principal, in *previewInput) (*previewOutput, error) {
	known, unknown := splitPermissions(in.Body.Permissions)
	direct := expandPermissions(known)

	out := &previewOutput{}
	out.Body.Allows = []allowDTO{}
	out.Body.Restrictions = []restrictionDTO{}
	out.Body.OtherRoles = []string{}
	out.Body.Unknown = unknown

	holderKind, holderID := in.Body.PrincipalKind, in.Body.PrincipalID
	var others []heldRole
	var rules map[string]*toolRules
	err := d.DB.Tx(tenant.WithOrg(ctx, p.OrgID), func(tx pgx.Tx) error {
		var err error
		if holderID != "" {
			if err := principalExists(ctx, tx, p.OrgID, holderKind, holderID); err != nil {
				return err
			}
			if out.Body.Holder, err = principalName(ctx, tx, holderKind, holderID); err != nil {
				return err
			}
			if others, err = heldRoles(ctx, tx, holderKind, holderID, in.Body.RoleID); err != nil {
				return err
			}
		}
		rules, err = readToolRules(ctx, tx)
		return err
	})
	if err != nil {
		return nil, err
	}

	// The evaluator's own answer for what this person already holds. It
	// is what settles the wildcard and anything a binding has since
	// stopped granting, so the roles read above only supply the names.
	already := map[string]bool{}
	if holderID != "" && d.Authz != nil {
		held, err := d.Authz.EffectivePermissions(ctx, holderPrincipal(p.OrgID, holderKind, holderID))
		if err != nil {
			return nil, err
		}
		for _, perm := range held {
			already[string(perm)] = true
		}
	}

	for _, group := range permissionCatalogue() {
		for _, perm := range group.Permissions {
			entry := allowDTO{ID: perm.ID, Description: perm.Description, FromThis: direct[perm.ID], FromOther: []string{}}
			for _, r := range others {
				if (r.perms[perm.ID] || r.perms[string(authz.Wildcard)]) && already[perm.ID] {
					entry.FromOther = append(entry.FromOther, r.name)
				}
			}
			if entry.FromThis || len(entry.FromOther) > 0 {
				out.Body.Allows = append(out.Body.Allows, entry)
			}
		}
	}
	for _, r := range others {
		out.Body.OtherRoles = append(out.Body.OtherRoles, r.name)
	}
	out.Body.Restrictions = d.restrictions(ctx, p.OrgID, in.Body.RoleID, holderKind, holderID, others, rules)
	return out, nil
}

// toolRules is what the access rules say about one tool: which roles are
// kept from it, and which few it is limited to.
type toolRules struct {
	id    string
	name  string
	deny  map[string]bool
	allow map[string]bool
}

// restrictions describes the tools whose answer a rule changes. With
// somebody named, the verdict is the evaluator's own for that person as
// things stand today; with nobody named it is what the rules say about
// the role being built.
func (d Deps) restrictions(ctx context.Context, orgID, roleID, holderKind, holderID string,
	others []heldRole, rules map[string]*toolRules,
) []restrictionDTO {
	out := []restrictionDTO{}
	roles := map[string]bool{}
	if roleID != "" {
		roles[roleID] = true
	}
	for _, r := range others {
		roles[r.id] = true
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return rules[ids[i]].name < rules[ids[j]].name })

	for _, id := range ids {
		rule := rules[id]
		denied, restricted, listed := false, len(rule.allow) > 0, false
		for held := range roles {
			if rule.deny[held] {
				denied = true
			}
			if rule.allow[held] {
				listed = true
			}
		}
		if listed {
			restricted = false
		}
		if !denied && !restricted && !listed {
			continue // no rule here touches the role or its holder
		}
		entry := restrictionDTO{ToolID: rule.id, ToolName: rule.name, Allowed: !denied && !restricted}
		switch {
		case denied:
			entry.Detail = "Kept from this tool by a rule, whatever else the role allows."
		case restricted:
			entry.Detail = "This tool is limited to particular roles, and none of these is among them."
		default:
			entry.Detail = "This tool is limited to particular roles, and one of these is among them."
		}
		// Where there is somebody to ask about, the evaluator decides:
		// it is the same code that would answer the real call, and it
		// weighs the rules against everything else they hold.
		if holderID != "" && d.Authz != nil {
			decision, err := d.Authz.Evaluate(ctx, holderPrincipal(orgID, holderKind, holderID),
				authz.ToolsInvoke, authz.Resource{ToolID: rule.id})
			if err == nil {
				entry.Allowed = decision.Allow
			}
		}
		out = append(out, entry)
	}
	return out
}

// holderPrincipal is the person or service account the preview is about,
// shaped the way the evaluator expects to be asked.
func holderPrincipal(orgID, kind, id string) *authz.Principal {
	p := &authz.Principal{Kind: authz.KindUser, ID: id, OrgID: orgID}
	if kind == "service_account" {
		p.Kind = authz.KindServiceAccount
	}
	return p
}

// expandPermissions turns the set somebody built into the set it means.
// The wildcard is a single tick that allows everything, and a preview
// that showed it as one line would be the one line that hides the rest.
func expandPermissions(perms []string) map[string]bool {
	set := map[string]bool{}
	for _, p := range perms {
		if p == string(authz.Wildcard) {
			for _, all := range authz.All() {
				set[string(all)] = true
			}
		}
		set[p] = true
	}
	return set
}

func heldRoles(ctx context.Context, tx pgx.Tx, kind, id, except string) ([]heldRole, error) {
	rows, err := tx.Query(ctx, `
SELECT r.id, r.name, r.permissions
FROM role_bindings b JOIN roles r ON r.id = b.role_id
WHERE b.principal_kind = $1 AND b.principal_id = $2 AND b.scope_kind = 'org'
  AND (b.expires_at IS NULL OR b.expires_at > now())
  AND r.id <> $3
ORDER BY r.name`, kind, id, except)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []heldRole{}
	for rows.Next() {
		var r heldRole
		var perms []string
		if err := rows.Scan(&r.id, &r.name, &perms); err != nil {
			return nil, err
		}
		r.perms = map[string]bool{}
		for _, p := range perms {
			r.perms[p] = true
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func readToolRules(ctx context.Context, tx pgx.Tx) (map[string]*toolRules, error) {
	rows, err := tx.Query(ctx, `
SELECT a.tool_id, t.name, a.role_id, a.effect
FROM tool_access_rules a JOIN tools t ON t.id = a.tool_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*toolRules{}
	for rows.Next() {
		var toolID, name, roleID, effect string
		if err := rows.Scan(&toolID, &name, &roleID, &effect); err != nil {
			return nil, err
		}
		rule := out[toolID]
		if rule == nil {
			rule = &toolRules{id: toolID, name: name, deny: map[string]bool{}, allow: map[string]bool{}}
			out[toolID] = rule
		}
		if effect == "deny" {
			rule.deny[roleID] = true
			continue
		}
		rule.allow[roleID] = true
	}
	return out, rows.Err()
}

// principalName resolves a holder to the name a screen should show. A
// principal with no name of its own is shown by its identifier rather
// than as nobody.
func principalName(ctx context.Context, tx pgx.Tx, kind, id string) (string, error) {
	var q string
	switch kind {
	case "service_account":
		q = `SELECT name FROM service_accounts WHERE id = $1`
	case "idp_group":
		q = `SELECT display_name FROM scim_groups WHERE id = $1`
	default:
		q = `SELECT COALESCE(NULLIF(name, ''), email) FROM users WHERE id = $1`
	}
	var name string
	err := tx.QueryRow(ctx, q, id).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return id, nil
	}
	if err != nil {
		return "", err
	}
	if name == "" {
		return id, nil
	}
	return name, nil
}

// permissionCatalogue describes the closed permission set in the order a
// screen should show it. The descriptions are the product's own words for
// what someone can do, which is the only form of this list a reader outside
// the team can act on.
//
// Anything in authz.All() that is missing below is appended rather than
// dropped, so a new permission shows up on the screen the day it is added
// instead of disappearing until someone remembers this file.
func permissionCatalogue() []permissionGroupDTO {
	groups := []permissionGroupDTO{
		{Resource: "organisation", Title: "Organisation", Permissions: []permissionDTO{
			{string(authz.OrgRead), "See the organisation, who is in it and how it is set up"},
			{string(authz.OrgUpdate), "Rename the organisation and change its details"},
			{string(authz.OrgDelete), "Delete the organisation and everything in it"},
			{string(authz.OrgMembersManage), "Add people, remove them and deactivate their accounts"},
			{string(authz.OrgSettingsManage), "Change organisation-wide settings, such as the password rules"},
			{string(authz.OrgBillingManage), "See and change the plan and the payment details"},
		}},
		{Resource: "connectors", Title: "Connectors", Permissions: []permissionDTO{
			{string(authz.ConnectorsRead), "See which connectors are installed and how they are configured"},
			{string(authz.ConnectorsCreate), "Install a connector from the catalogue or from a specification"},
			{string(authz.ConnectorsUpdate), "Change a connector's settings and instructions"},
			{string(authz.ConnectorsDelete), "Remove a connector, and every tool that came with it"},
			{string(authz.ConnectorsAuth), "Set the credentials a connector uses to sign in to the service behind it"},
			{string(authz.ConnectorsTest), "Send a test call through a connector to the service behind it"},
		}},
		{Resource: "tools", Title: "Tools", Permissions: []permissionDTO{
			{string(authz.ToolsRead), "See the available tools and what each one expects"},
			{string(authz.ToolsUpdate), "Turn tools on and off and rewrite how they are described to a model"},
			{string(authz.ToolsInvoke), "Run a tool"},
			{string(authz.ToolsInvokeDestr), "Run tools marked destructive, which change or remove data in the service behind them"},
		}},
		{Resource: "servers", Title: "MCP servers", Permissions: []permissionDTO{
			{string(authz.ServersRead), "See the MCP servers and which connectors each one offers"},
			{string(authz.ServersCreate), "Create an MCP server for clients to connect to"},
			{string(authz.ServersUpdate), "Change an MCP server, including which connectors it offers"},
			{string(authz.ServersDelete), "Delete an MCP server, which disconnects every client using it"},
		}},
		{Resource: "access", Title: "Access", Permissions: []permissionDTO{
			{string(authz.RolesRead), "See the roles and who holds them"},
			{string(authz.RolesManage), "Give people roles and take them away, including roles stronger than their own"},
			{string(authz.APIKeysSelf), "Create and revoke their own API keys"},
			{string(authz.APIKeysOrg), "Create and revoke API keys belonging to anyone in the organisation"},
			{string(authz.ServiceAccounts), "Create service accounts and issue the credentials they sign in with"},
		}},
		{Resource: "identity", Title: "Sign-in", Permissions: []permissionDTO{
			{string(authz.IdpManage), "Set up single sign-on and change how people sign in"},
			{string(authz.ScimManage), "Let an identity provider create and deactivate accounts automatically"},
		}},
		{Resource: "audit", Title: "Audit trail", Permissions: []permissionDTO{
			{string(authz.AuditRead), "Read the record of what everyone has done"},
			{string(authz.AuditExport), "Download a copy of that record"},
			{string(authz.AuditPolicy), "Decide how much of a tool call's input and output the record keeps, and for how long"},
		}},
		{Resource: "governance", Title: "Approvals and data protection", Permissions: []permissionDTO{
			{string(authz.ApprovalsRequest), "Ask for approval to run something that needs it"},
			{string(authz.ApprovalsDecide), "Approve or refuse someone else's request"},
			{string(authz.DLPManage), "Change the rules that hide sensitive data passing through"},
		}},
		{Resource: "operations", Title: "Recovery", Permissions: []permissionDTO{
			{string(authz.RevisionsRollback), "Put a connector, tool or server back to an earlier version"},
			{string(authz.SecretsRotate), "Replace stored credentials and encryption keys with new ones"},
		}},
		{Resource: "all", Title: "Everything", Permissions: []permissionDTO{
			{string(authz.Wildcard), "Everything in this organisation, including deleting it"},
		}},
	}
	described := map[string]bool{}
	for _, g := range groups {
		for _, p := range g.Permissions {
			described[p.ID] = true
		}
	}
	var missing []permissionDTO
	for _, p := range authz.All() {
		if !described[string(p)] {
			missing = append(missing, permissionDTO{ID: string(p), Description: string(p)})
		}
	}
	if len(missing) > 0 {
		groups = append(groups, permissionGroupDTO{Resource: "other", Title: "Other", Permissions: missing})
	}
	return groups
}
