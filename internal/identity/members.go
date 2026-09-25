package identity

import (
	"context"
	"errors"
	"time"
)

// Members are the people in an organisation: a row in organization_members
// and the role bindings that say what they may do there. An administrator
// can list them, change their role, deactivate or reactivate them, and
// remove them. Deactivating or removing someone ends every session, API key
// and refresh token they hold.

// Errors.
var (
	// ErrSelf refuses a lifecycle or role change aimed at the caller.
	ErrSelf = errors.New("you cannot change your own membership")
	// ErrLastOwner refuses a change that would leave no active owner.
	ErrLastOwner = errors.New("the organisation must keep at least one active owner")
	// ErrScimManaged refuses deactivating or removing a member that an
	// identity provider provisions through SCIM.
	ErrScimManaged = errors.New("this member is managed by your identity provider; deactivate or remove them there")
	// ErrNotMember is returned for a user who is not in the organisation,
	// including one in another organisation.
	ErrNotMember = errors.New("no such member")

	// errNotImplemented marks a signature whose body is not written yet.
	errNotImplemented = errors.New("not implemented")
)

// MemberStatus values.
const (
	MemberActive      = "active"
	MemberDeactivated = "deactivated"
)

// MemberSource values: how a member signs in.
const (
	SourcePassword = "password"
	SourceSSO      = "sso"
	SourceSCIM     = "scim"
)

// Member is a person in an organisation.
type Member struct {
	UserID       string
	Email        string
	Name         string
	Status       string // MemberActive or MemberDeactivated
	Source       string // SourcePassword, SourceSSO or SourceSCIM
	Roles        []MemberRole
	LastSignInAt *time.Time
	JoinedAt     time.Time
	ScimManaged  bool
}

// MemberRole is one role binding a member holds.
type MemberRole struct {
	RoleID    string
	RoleName  string
	BindingID string
	Source    string // manual, sso, scim or invite
	ScopeKind string // org, server, connector or tool
}

// ListMembers returns every member of the organisation with their roles.
func (s *Service) ListMembers(ctx context.Context, orgID string) ([]Member, error) {
	return nil, errNotImplemented
}

// SetMemberStatus deactivates (active false) or reactivates a member and
// returns them before and after the change.
func (s *Service) SetMemberStatus(ctx context.Context, orgID, actorID, userID string, active bool) (before, after Member, err error) {
	return Member{}, Member{}, errNotImplemented
}

// SetMemberRole replaces a member's manual organisation-wide roles with
// roleID and returns them before and after the change.
func (s *Service) SetMemberRole(ctx context.Context, orgID, actorID, userID, roleID string) (before, after Member, err error) {
	return Member{}, Member{}, errNotImplemented
}

// RemoveMember removes a member and their role bindings from the
// organisation and returns them as they were. The user record stays.
func (s *Service) RemoveMember(ctx context.Context, orgID, actorID, userID string) (Member, error) {
	return Member{}, errNotImplemented
}
