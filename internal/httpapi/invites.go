package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

// --- invites ---------------------------------------------------------------

// An administrator invites someone by email with a role and gets a link
// back once; nothing is mailed. The person holding the link looks it up
// and accepts it without a session in the organisation. The token travels
// in a POST body, never in a path, because paths are logged.

// inviteDTO is an invite as an administrator sees it. It never carries the
// token.
type inviteDTO struct {
	ID         string     `json:"id"`
	Email      string     `json:"email"`
	RoleID     string     `json:"roleId"`
	RoleName   string     `json:"roleName"`
	InvitedBy  string     `json:"invitedBy,omitempty" doc:"The user who created the invite"`
	Status     string     `json:"status" enum:"pending,accepted,revoked,expired"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	AcceptedAt *time.Time `json:"acceptedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

type invitesOutput struct {
	Body struct {
		Invites []inviteDTO `json:"invites" nullable:"false"`
	}
}

type createInviteInput struct {
	Body struct {
		Email         string `json:"email" format:"email"`
		RoleID        string `json:"roleId" minLength:"1"`
		ExpiresInDays int    `json:"expiresInDays,omitempty" minimum:"1" maximum:"30" doc:"How long the link works; 7 days when omitted"`
	}
}

type createInviteOutput struct {
	Body struct {
		Invite inviteDTO `json:"invite"`
		URL    string    `json:"url" doc:"The link to send. Shown once; it cannot be read back."`
	}
}

type revokeInviteInput struct {
	ID string `path:"id"`
}

// inviteLookupDTO is what the holder of a link sees before accepting.
type inviteLookupDTO struct {
	OrgName              string    `json:"orgName"`
	Email                string    `json:"email"`
	RoleName             string    `json:"roleName"`
	ExpiresAt            time.Time `json:"expiresAt"`
	RegistrationRequired bool      `json:"registrationRequired" doc:"No account exists for the email; accepting without a session creates one"`
}

type inviteLookupInput struct {
	Body struct {
		Token string `json:"token" minLength:"1" maxLength:"128"`
	}
}

type inviteLookupOutput struct {
	Body inviteLookupDTO
}

// acceptInviteInput accepts an invite. A signed-in caller sends only the
// token; an anonymous one sends a password (and optionally a name) for the
// account it creates.
type acceptInviteInput struct {
	Body struct {
		Token    string `json:"token" minLength:"1" maxLength:"128"`
		Name     string `json:"name,omitempty" maxLength:"200"`
		Password string `json:"password,omitempty" doc:"Required when there is no session"`
	}
}

func (d Deps) inviteRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "invites-list", Method: http.MethodGet,
		Path: "/api/v1/org/invites", Summary: "List the organisation's invites",
		Tags: []string{"invites"}, Security: sessionSecurity},
		func(_ context.Context, _ *struct{}) (*invitesOutput, error) {
			return nil, huma.Error501NotImplemented("not implemented")
		})

	huma.Register(api, huma.Operation{OperationID: "invites-create", Method: http.MethodPost,
		Path: "/api/v1/org/invites", Summary: "Invite someone by email and get the link to send them",
		Tags: []string{"invites"}, Security: sessionSecurity, DefaultStatus: http.StatusCreated},
		func(_ context.Context, _ *createInviteInput) (*createInviteOutput, error) {
			return nil, huma.Error501NotImplemented("not implemented")
		})

	huma.Register(api, huma.Operation{OperationID: "invites-revoke", Method: http.MethodDelete,
		Path: "/api/v1/org/invites/{id}", Summary: "Revoke an open invite",
		Tags: []string{"invites"}, Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(_ context.Context, _ *revokeInviteInput) (*struct{}, error) {
			return nil, huma.Error501NotImplemented("not implemented")
		})

	// The two below need no session, like register and login.
	huma.Register(api, huma.Operation{OperationID: "invite-lookup", Method: http.MethodPost,
		Path: "/api/v1/invites/lookup", Summary: "Show what an invite link is for",
		Tags: []string{"invites"}},
		func(_ context.Context, _ *inviteLookupInput) (*inviteLookupOutput, error) {
			return nil, huma.Error501NotImplemented("not implemented")
		})

	huma.Register(api, huma.Operation{OperationID: "invite-accept", Method: http.MethodPost,
		Path: "/api/v1/invites/accept", Summary: "Accept an invite, creating an account when there is no session",
		Tags: []string{"invites"}},
		func(_ context.Context, _ *acceptInviteInput) (*sessionOutput, error) {
			return nil, huma.Error501NotImplemented("not implemented")
		})
}
