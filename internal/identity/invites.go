package identity

import (
	"context"
	"errors"
	"time"
)

// An invite lets an administrator bring someone into an organisation with a
// role. The server returns a link carrying a random token once and keeps
// only its SHA-256 digest; nothing is mailed. Whoever opens the link looks
// the invite up and accepts it, signed in as the invited address or by
// creating an account for it, whatever the open-registration setting says.

// Errors.
var (
	// ErrInviteInvalid covers an unknown, expired, revoked or already
	// accepted token alike, so a caller learns nothing by guessing.
	ErrInviteInvalid = errors.New("this invitation is not valid or has expired")
	// ErrInviteEmailMismatch refuses a signed-in user whose email is not
	// the one the invite was made for.
	ErrInviteEmailMismatch = errors.New("this invitation is for a different email address")
	// ErrInviteExists refuses a second open invite for the same address,
	// or an invite for someone who is already a member.
	ErrInviteExists = errors.New("an invitation for this email address is already open")
)

// InviteStatus values.
const (
	InvitePending  = "pending"
	InviteAccepted = "accepted"
	InviteRevoked  = "revoked"
	InviteExpired  = "expired"
)

// Invite is an invitation as an administrator sees it. It never carries
// the token.
type Invite struct {
	ID         string
	OrgID      string
	Email      string
	RoleID     string
	RoleName   string
	InvitedBy  string
	Status     string // InvitePending, InviteAccepted, InviteRevoked or InviteExpired
	ExpiresAt  time.Time
	AcceptedAt *time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

// InviteLookup is what the person holding the link may see before
// accepting.
type InviteLookup struct {
	OrgID    string
	OrgName  string
	Email    string
	RoleName string
	// ExpiresAt is when the link stops working.
	ExpiresAt time.Time
	// RegistrationRequired is true when no account exists for the email,
	// so accepting anonymously creates one.
	RegistrationRequired bool
}

// AcceptInput is what an anonymous caller sends to create their account.
// A signed-in caller sends neither field.
type AcceptInput struct {
	Name     string
	Password string
}

// CreateInvite opens an invite for email with roleID, valid for ttl, and
// returns it with the token. The token is not stored and cannot be read
// back.
func (s *Service) CreateInvite(ctx context.Context, orgID, actorID, email, roleID string, ttl time.Duration) (inv Invite, token string, err error) {
	return Invite{}, "", errNotImplemented
}

// ListInvites returns the organisation's invites, newest first.
func (s *Service) ListInvites(ctx context.Context, orgID string) ([]Invite, error) {
	return nil, errNotImplemented
}

// RevokeInvite revokes an open invite and returns it.
func (s *Service) RevokeInvite(ctx context.Context, orgID, id string) (Invite, error) {
	return Invite{}, errNotImplemented
}

// LookupInvite resolves a token to what its holder may see. It needs no
// session. Every failure is ErrInviteInvalid.
func (s *Service) LookupInvite(ctx context.Context, token string) (*InviteLookup, error) {
	return nil, errNotImplemented
}

// AcceptInvite consumes the invite for token. signedIn is the caller's user
// when they have a session, nil otherwise; an anonymous caller must supply
// a password in in. It returns the member and the organisation joined.
func (s *Service) AcceptInvite(ctx context.Context, token string, signedIn *User, in AcceptInput) (*User, *Org, error) {
	return nil, nil, errNotImplemented
}
