package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/identity"
)

// --- members ---------------------------------------------------------------

// The people in the organisation and what an administrator can do about
// them: change their role, deactivate or reactivate them, remove them.
// Reading the list needs org:read; every change needs org:members:manage.

// memberDTO is a member as the members screen shows them.
type memberDTO struct {
	UserID       string          `json:"userId"`
	Email        string          `json:"email"`
	Name         string          `json:"name,omitempty"`
	Status       string          `json:"status" enum:"active,deactivated"`
	Source       string          `json:"source" enum:"password,sso,scim" doc:"How the member signs in"`
	Roles        []memberRoleDTO `json:"roles" nullable:"false"`
	LastSignInAt *time.Time      `json:"lastSignInAt,omitempty"`
	JoinedAt     time.Time       `json:"joinedAt"`
	IsSelf       bool            `json:"isSelf" doc:"The member is the caller"`
	ScimManaged  bool            `json:"scimManaged" doc:"An identity provider provisions this member; deactivate or remove them there"`
}

// memberRoleDTO is one role binding a member holds.
type memberRoleDTO struct {
	RoleID    string `json:"roleId"`
	RoleName  string `json:"roleName"`
	BindingID string `json:"bindingId"`
	Source    string `json:"source" doc:"manual, sso, scim or invite"`
	ScopeKind string `json:"scopeKind" enum:"org,server,connector,tool"`
}

type membersOutput struct {
	Body struct {
		Members []memberDTO `json:"members" nullable:"false"`
	}
}

type memberOutput struct {
	Body memberDTO
}

// updateMemberInput changes one thing about a member: send status or
// roleId.
type updateMemberInput struct {
	UserID string `path:"userId"`
	Body   struct {
		Status *string `json:"status,omitempty" enum:"active,deactivated"`
		RoleID *string `json:"roleId,omitempty" doc:"Replaces the member's manually granted organisation-wide roles"`
	}
}

type removeMemberInput struct {
	UserID string `path:"userId"`
}

func (d Deps) memberRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "members-list", Method: http.MethodGet,
		Path: "/api/v1/org/members", Summary: "List the members of the organisation and their roles",
		Tags: []string{"members"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*membersOutput, error) {
			p, err := d.require(ctx, authz.OrgRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			members, err := d.Identity.ListMembers(ctx, p.OrgID)
			if err != nil {
				return nil, humaErr(err)
			}
			out := &membersOutput{}
			out.Body.Members = make([]memberDTO, 0, len(members))
			for _, m := range members {
				out.Body.Members = append(out.Body.Members, toMemberDTO(m, p.ID))
			}
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "members-update", Method: http.MethodPatch,
		Path: "/api/v1/org/members/{userId}", Summary: "Change a member's role, or deactivate or reactivate them",
		Tags: []string{"members"}, Security: sessionSecurity},
		func(ctx context.Context, in *updateMemberInput) (*memberOutput, error) {
			p, err := d.requireFresh(ctx, authz.OrgMembersManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			switch {
			case in.Body.Status != nil && in.Body.RoleID == nil:
				return d.setMemberStatus(ctx, p, in.UserID, *in.Body.Status == identity.MemberActive)
			case in.Body.RoleID != nil && in.Body.Status == nil:
				return d.setMemberRole(ctx, p, in.UserID, *in.Body.RoleID)
			default:
				return nil, huma.Error400BadRequest("send either status or roleId")
			}
		})

	huma.Register(api, huma.Operation{OperationID: "members-remove", Method: http.MethodDelete,
		Path: "/api/v1/org/members/{userId}", Summary: "Remove a member from the organisation",
		Tags: []string{"members"}, Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *removeMemberInput) (*struct{}, error) {
			p, err := d.requireFresh(ctx, authz.OrgMembersManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			m, err := d.Identity.RemoveMember(ctx, p.OrgID, p.ID, in.UserID)
			if err != nil {
				d.adminFailed(ctx, "member.remove", "user", in.UserID, err)
				return nil, humaErr(err)
			}
			d.admin(ctx, "member.remove", "user", m.UserID, m.Email, audit.Deleted(toMemberDTO(m, p.ID)))
			d.invalidate(p.OrgID, "user", m.UserID)
			return nil, nil //nolint:nilnil // huma's no-content shape
		})
}

// setMemberStatus deactivates or reactivates a member.
func (d Deps) setMemberStatus(ctx context.Context, p *authz.Principal, userID string, active bool) (*memberOutput, error) {
	action := "member.deactivate"
	if active {
		action = "member.reactivate"
	}
	before, after, revoked, err := d.Identity.SetMemberStatus(ctx, p.OrgID, p.ID, userID, active)
	if err != nil {
		d.adminFailed(ctx, action, "user", userID, err)
		return nil, humaErr(err)
	}
	dto := toMemberDTO(after, p.ID)
	var meta map[string]any
	if !active {
		meta = map[string]any{"revokedTokens": revoked}
	}
	d.emit(ctx, audit.Event{Category: audit.CategoryAdmin, Action: action, Outcome: audit.Success,
		TargetKind: "user", TargetID: after.UserID, TargetDisplay: after.Email,
		Diff: audit.Changes(toMemberDTO(before, p.ID), dto), Meta: meta})
	d.invalidate(p.OrgID, "user", after.UserID)
	return &memberOutput{Body: dto}, nil
}

// setMemberRole replaces a member's manual organisation-wide roles. Making
// someone an owner hands them everything, so it takes an owner to do it,
// the same rule invitations follow.
func (d Deps) setMemberRole(ctx context.Context, p *authz.Principal, userID, roleID string) (*memberOutput, error) {
	if roleID == ownerRoleID {
		if _, err := d.require(ctx, authz.Wildcard, authz.Resource{}); err != nil {
			d.adminFailed(ctx, "member.role.set", "user", userID, errOwnerGrant)
			return nil, huma.Error403Forbidden(errOwnerGrant.Error())
		}
	}
	before, after, err := d.Identity.SetMemberRole(ctx, p.OrgID, p.ID, userID, roleID)
	if err != nil {
		d.adminFailed(ctx, "member.role.set", "user", userID, err)
		return nil, humaErr(err)
	}
	dto := toMemberDTO(after, p.ID)
	d.admin(ctx, "member.role.set", "user", after.UserID, after.Email, audit.Changes(toMemberDTO(before, p.ID), dto))
	d.invalidate(p.OrgID, "user", after.UserID)
	return &memberOutput{Body: dto}, nil
}

// errOwnerGrant refuses making someone an owner without being one.
var errOwnerGrant = errors.New("only an owner can make someone an owner")

func toMemberDTO(m identity.Member, callerID string) memberDTO {
	roles := make([]memberRoleDTO, 0, len(m.Roles))
	for _, r := range m.Roles {
		roles = append(roles, memberRoleDTO{RoleID: r.RoleID, RoleName: r.RoleName, BindingID: r.BindingID,
			Source: r.Source, ScopeKind: r.ScopeKind})
	}
	return memberDTO{UserID: m.UserID, Email: m.Email, Name: m.Name, Status: m.Status, Source: m.Source,
		Roles: roles, LastSignInAt: m.LastSignInAt, JoinedAt: m.JoinedAt,
		IsSelf: m.UserID == callerID, ScimManaged: m.ScimManaged}
}

// Stable codes a client reads from errors[].value on a member or invite
// 409, so it can explain the refusal without matching on the message.
const (
	conflictSelf         = "self"
	conflictLastOwner    = "last_owner"
	conflictScimManaged  = "scim_managed"
	conflictInviteExists = "invite_exists"
)

// memberErr maps the identity errors of members and invites to a reply,
// or returns nil for any other error.
func memberErr(err error) error {
	code := ""
	switch {
	case errors.Is(err, identity.ErrSelf):
		code = conflictSelf
	case errors.Is(err, identity.ErrLastOwner):
		code = conflictLastOwner
	case errors.Is(err, identity.ErrScimManaged):
		code = conflictScimManaged
	case errors.Is(err, identity.ErrInviteExists):
		code = conflictInviteExists
	case errors.Is(err, identity.ErrNotMember), errors.Is(err, identity.ErrNoSuchRole),
		errors.Is(err, identity.ErrInviteInvalid):
		return huma.Error404NotFound(err.Error())
	case errors.Is(err, identity.ErrInviteEmailMismatch):
		return huma.Error403Forbidden(err.Error())
	default:
		return nil
	}
	return huma.Error409Conflict(err.Error(), &huma.ErrorDetail{Location: "body", Message: err.Error(), Value: code})
}
