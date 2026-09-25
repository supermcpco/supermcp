package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

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
		func(_ context.Context, _ *struct{}) (*membersOutput, error) {
			return nil, huma.Error501NotImplemented("not implemented")
		})

	huma.Register(api, huma.Operation{OperationID: "members-update", Method: http.MethodPatch,
		Path: "/api/v1/org/members/{userId}", Summary: "Change a member's role, or deactivate or reactivate them",
		Tags: []string{"members"}, Security: sessionSecurity},
		func(_ context.Context, _ *updateMemberInput) (*memberOutput, error) {
			return nil, huma.Error501NotImplemented("not implemented")
		})

	huma.Register(api, huma.Operation{OperationID: "members-remove", Method: http.MethodDelete,
		Path: "/api/v1/org/members/{userId}", Summary: "Remove a member from the organisation",
		Tags: []string{"members"}, Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(_ context.Context, _ *removeMemberInput) (*struct{}, error) {
			return nil, huma.Error501NotImplemented("not implemented")
		})
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
	case errors.Is(err, identity.ErrNotMember), errors.Is(err, identity.ErrInviteInvalid):
		return huma.Error404NotFound(err.Error())
	case errors.Is(err, identity.ErrInviteEmailMismatch):
		return huma.Error403Forbidden(err.Error())
	default:
		return nil
	}
	return huma.Error409Conflict(err.Error(), &huma.ErrorDetail{Location: "body", Message: err.Error(), Value: code})
}
