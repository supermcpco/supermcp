package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/identity"
)

// --- invites ---------------------------------------------------------------

// An administrator invites someone by email with a role and gets a link
// back once; nothing is mailed. The person holding the link looks it up
// and accepts it without a session in the organisation. The token travels
// in a POST body, never in a path, because paths are logged.

// inviteDTO is an invite as an administrator sees it. It never carries the
// token.
type inviteDTO struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	RoleID        string     `json:"roleId"`
	RoleName      string     `json:"roleName"`
	InvitedBy     string     `json:"invitedBy,omitempty" doc:"The id of the user who created the invite"`
	InvitedByName string     `json:"invitedByName,omitempty" doc:"The inviter's name, or address when they have no name; absent once they have left the organisation"`
	Status        string     `json:"status" enum:"pending,accepted,revoked,expired"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	AcceptedAt    *time.Time `json:"acceptedAt,omitempty"`
	RevokedAt     *time.Time `json:"revokedAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
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
	// PasswordPolicy is what the new account's password must meet. The
	// policy endpoint needs a session, which the holder of a link lacks.
	PasswordPolicy *identity.PasswordPolicy `json:"passwordPolicy,omitempty" doc:"The organisation's password policy; present only when registrationRequired is true"`
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
		func(ctx context.Context, _ *struct{}) (*invitesOutput, error) {
			p, err := d.require(ctx, authz.OrgMembersManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			list, err := d.Identity.ListInvites(ctx, p.OrgID)
			if err != nil {
				return nil, inviteErr(err)
			}
			out := &invitesOutput{}
			out.Body.Invites = make([]inviteDTO, 0, len(list))
			for _, inv := range list {
				out.Body.Invites = append(out.Body.Invites, toInviteDTO(inv))
			}
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "invites-create", Method: http.MethodPost,
		Path: "/api/v1/org/invites", Summary: "Invite someone by email and get the link to send them",
		Tags: []string{"invites"}, Security: sessionSecurity, DefaultStatus: http.StatusCreated},
		func(ctx context.Context, in *createInviteInput) (*createInviteOutput, error) {
			p, err := d.requireFresh(ctx, authz.OrgMembersManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			// Inviting to a role that allows everything is handing it out,
			// so it takes holding it. Asked of the evaluator rather than
			// the role list so a scoped key never qualifies.
			holdsAll := true
			if err := d.Authz.Require(ctx, authz.Wildcard, authz.Resource{}); err != nil {
				if !errors.Is(err, authz.ErrDenied) {
					return nil, fmt.Errorf("check wildcard: %w", err)
				}
				holdsAll = false
			}
			inv, token, err := d.Identity.CreateInvite(ctx, p.OrgID, p.ID, identity.InviteInput{
				Email: in.Body.Email, RoleID: in.Body.RoleID,
				TTL: time.Duration(in.Body.ExpiresInDays) * 24 * time.Hour, ActorHoldsAll: holdsAll})
			if err != nil {
				d.adminFailed(ctx, "invite.create", "invite", "", err)
				return nil, inviteErr(err)
			}
			dto := toInviteDTO(inv)
			// The diff is the invite as listed: never the token or the link.
			d.admin(ctx, "invite.create", "invite", inv.ID, inv.Email, audit.Created(dto))
			out := &createInviteOutput{}
			out.Body.Invite = dto
			out.Body.URL = d.inviteURL(token)
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "invites-revoke", Method: http.MethodDelete,
		Path: "/api/v1/org/invites/{id}", Summary: "Revoke an open invite",
		Tags: []string{"invites"}, Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *revokeInviteInput) (*struct{}, error) {
			p, err := d.require(ctx, authz.OrgMembersManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			inv, err := d.Identity.RevokeInvite(ctx, p.OrgID, in.ID)
			if err != nil {
				d.adminFailed(ctx, "invite.revoke", "invite", in.ID, err)
				return nil, inviteErr(err)
			}
			after := toInviteDTO(inv)
			before := after
			before.RevokedAt = nil
			before.Status = identity.InvitePending
			if inv.RevokedAt != nil && !inv.ExpiresAt.After(*inv.RevokedAt) {
				before.Status = identity.InviteExpired
			}
			d.admin(ctx, "invite.revoke", "invite", inv.ID, inv.Email, audit.Changes(before, after))
			return nil, nil
		})

	// The two below need no session, like register and login.
	huma.Register(api, huma.Operation{OperationID: "invite-lookup", Method: http.MethodPost,
		Path: "/api/v1/invites/lookup", Summary: "Show what an invite link is for",
		Tags: []string{"invites"}},
		func(ctx context.Context, in *inviteLookupInput) (*inviteLookupOutput, error) {
			ip, _ := ctx.Value(ipKey).(string)
			l, err := d.Identity.LookupInvite(ctx, in.Body.Token, ip)
			if err != nil {
				return nil, inviteErr(err)
			}
			return &inviteLookupOutput{Body: inviteLookupDTO{OrgName: l.OrgName, Email: l.Email, RoleName: l.RoleName,
				ExpiresAt: l.ExpiresAt, RegistrationRequired: l.RegistrationRequired, PasswordPolicy: l.PasswordPolicy}}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "invite-accept", Method: http.MethodPost,
		Path: "/api/v1/invites/accept", Summary: "Accept an invite, creating an account when there is no session",
		Tags: []string{"invites"}},
		d.acceptInvite)
}

// acceptInvite joins the caller to the invite's organisation. A signed-in
// caller keeps their session, now pointed at that organisation; an
// anonymous one gets a new account and a session for it.
func (d Deps) acceptInvite(ctx context.Context, in *acceptInviteInput) (*sessionOutput, error) {
	ip, _ := ctx.Value(ipKey).(string)
	p, ok := authz.From(ctx)
	signedIn := ok && p.Kind == authz.KindUser && p.AuthMethod == "session" && p.SessionID != ""
	userID := ""
	if signedIn {
		userID = p.ID
	}
	res, err := d.Identity.AcceptInvite(ctx, in.Body.Token, ip, userID,
		identity.AcceptInput{Name: in.Body.Name, Password: in.Body.Password})
	if err != nil {
		d.authEvent(ctx, "invite.accept", audit.Failure, "", errorMeta(ctx, nil, "reason", err))
		return nil, inviteErr(err)
	}
	d.invalidate(res.Org.ID, "user", res.User.ID)

	sessionID := ""
	if signedIn {
		sessionID = p.SessionID
	}
	if res.Created {
		d.emitAs(ctx, audit.Event{OrgID: res.Org.ID, Category: audit.CategoryAuth, Action: "account.register",
			Outcome: audit.Success, ActorKind: "user", ActorID: res.User.ID, ActorDisplay: res.User.Email,
			TargetKind: "organization", TargetID: res.Org.ID, TargetDisplay: res.Org.Name,
			Meta: map[string]any{"via": "invite", "inviteId": res.InviteID}})
	}
	d.emitAs(ctx, audit.Event{OrgID: res.Org.ID, Category: audit.CategoryAdmin, Action: "member.join",
		Outcome: audit.Success, ActorKind: "user", ActorID: res.User.ID, ActorDisplay: res.User.Email,
		SessionID: sessionID, TargetKind: "user", TargetID: res.User.ID, TargetDisplay: res.User.Email,
		Meta: map[string]any{"via": "invite", "inviteId": res.InviteID, "roleId": res.RoleID,
			"roleName": res.RoleName, "invitedBy": res.InvitedBy}})

	if !signedIn {
		return d.startSession(ctx, &res.User, &res.Org)
	}
	sess, err := d.Identity.LoadSession(ctx, p.SessionID)
	if err != nil {
		return nil, humaErr(err)
	}
	if err := d.Identity.SwitchOrg(ctx, sess, res.Org.ID); err != nil {
		return nil, fmt.Errorf("switch to the joined organisation: %w", err)
	}
	p.OrgID = res.Org.ID
	return d.sessionBodyFor(ctx, p)
}

// inviteURL is the link an administrator sends. The token is in the path
// of a page the browser renders; the page posts it to the API in a body.
func (d Deps) inviteURL(token string) string {
	base := ""
	if d.Config != nil && d.Config.PublicURL != nil {
		base = strings.TrimSuffix(d.Config.PublicURL.String(), "/")
	}
	return base + "/invite/" + token
}

func toInviteDTO(inv identity.Invite) inviteDTO {
	return inviteDTO{ID: inv.ID, Email: inv.Email, RoleID: inv.RoleID, RoleName: inv.RoleName, InvitedBy: inv.InvitedBy,
		InvitedByName: inv.InvitedByName, Status: inv.Status, ExpiresAt: inv.ExpiresAt, AcceptedAt: inv.AcceptedAt, RevokedAt: inv.RevokedAt,
		CreatedAt: inv.CreatedAt}
}

// Stable codes for the invite refusals humaErr does not know.
const (
	conflictAccountExists = "account_exists"
	conflictAlreadyMember = "already_member"
	conflictInviteLimit   = "invite_limit"
)

// inviteErr maps the invite refusals that are particular to this file,
// and hands everything else to humaErr.
func inviteErr(err error) error {
	code := ""
	switch {
	case errors.Is(err, identity.ErrInviteSignInFirst):
		// Located at the password: it is what the caller should not have
		// sent, and where the screen puts the explanation.
		return huma.Error409Conflict(err.Error(), &huma.ErrorDetail{Location: "body.password", Message: err.Error(),
			Value: conflictAccountExists})
	case errors.Is(err, identity.ErrAlreadyMember):
		code = conflictAlreadyMember
	case errors.Is(err, identity.ErrInviteLimit):
		code = conflictInviteLimit
	case errors.Is(err, identity.ErrInviteRole):
		return huma.Error404NotFound(err.Error())
	case errors.Is(err, identity.ErrInviteRoleTooBroad):
		return huma.Error403Forbidden(err.Error())
	case errors.Is(err, identity.ErrInviteEmail), errors.Is(err, identity.ErrInviteTTL),
		errors.Is(err, identity.ErrInviteSignedIn):
		return huma.Error400BadRequest(err.Error())
	default:
		return humaErr(err)
	}
	return huma.Error409Conflict(err.Error(), &huma.ErrorDetail{Location: "body", Message: err.Error(), Value: code})
}
