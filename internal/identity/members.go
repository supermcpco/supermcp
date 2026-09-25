package identity

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/tenant"
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
	// ErrNoSuchRole refuses a role the organisation cannot use: unknown,
	// or another organisation's own.
	ErrNoSuchRole = errors.New("no such role")
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

// ownerRole is the built-in role that can do anything. The organisation
// must always keep one active member who holds it organisation-wide, or
// nobody is left who can grant it back.
const ownerRole = "role_owner"

// Revocation reasons recorded on the sessions, keys and refresh tokens a
// lifecycle change ends.
const (
	reasonDeactivated = "deactivated by administrator"
	reasonRemoved     = "removed by administrator"
)

// memberSelect reads members with everything the list shows in one
// statement. Row-level security limits every table to the current
// organisation (users, sessions and identity links through membership or
// their provider), so the source and last sign-in are what this
// organisation can see. Expired role bindings are left out: they grant
// nothing.
const memberSelect = `
SELECT u.id, u.email, u.name,
       m.deactivated_at IS NOT NULL,
       m.created_at,
       su.user_id IS NOT NULL,
       EXISTS (SELECT 1 FROM user_identities ui WHERE ui.user_id = u.id)
           OR EXISTS (SELECT 1 FROM saml_identities si WHERE si.user_id = u.id),
       u.password_hash IS NOT NULL,
       GREATEST((SELECT max(s.created_at) FROM sessions s WHERE s.user_id = u.id),
                (SELECT max(ui.last_login_at) FROM user_identities ui WHERE ui.user_id = u.id),
                (SELECT max(si.last_login_at) FROM saml_identities si WHERE si.user_id = u.id)),
       rb.role_ids, rb.role_names, rb.binding_ids, rb.sources, rb.scope_kinds
FROM organization_members m
JOIN users u ON u.id = m.user_id
LEFT JOIN scim_users su ON su.organization_id = m.organization_id AND su.user_id = m.user_id
LEFT JOIN LATERAL (
    SELECT array_agg(b.role_id    ORDER BY b.created_at, b.id) AS role_ids,
           array_agg(r.name       ORDER BY b.created_at, b.id) AS role_names,
           array_agg(b.id         ORDER BY b.created_at, b.id) AS binding_ids,
           array_agg(b.source     ORDER BY b.created_at, b.id) AS sources,
           array_agg(b.scope_kind ORDER BY b.created_at, b.id) AS scope_kinds
    FROM role_bindings b JOIN roles r ON r.id = b.role_id
    WHERE b.organization_id = m.organization_id AND b.principal_kind = 'user' AND b.principal_id = m.user_id
      AND (b.expires_at IS NULL OR b.expires_at > now())
) rb ON true
WHERE m.organization_id = $1`

// activeOwnersSelect is the members who hold the owner role across the
// whole organisation, unexpired, and are not deactivated.
const activeOwnersSelect = `
WITH owners AS (
    SELECT b.principal_id FROM role_bindings b
    JOIN organization_members m ON m.organization_id = b.organization_id AND m.user_id = b.principal_id
    WHERE b.organization_id = $1 AND b.role_id = '` + ownerRole + `'
      AND b.principal_kind = 'user' AND b.scope_kind = 'org'
      AND (b.expires_at IS NULL OR b.expires_at > now())
      AND m.deactivated_at IS NULL
)`

// ListMembers returns every member of the organisation with their roles.
func (s *Service) ListMembers(ctx context.Context, orgID string) ([]Member, error) {
	out := []Member{}
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, memberSelect+` ORDER BY m.created_at, u.id`, orgID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			m, err := scanMember(rows)
			if err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	return out, nil
}

// SetMemberStatus deactivates (active false) or reactivates a member and
// returns them before and after the change. Deactivating ends every
// session, API key and refresh token the member holds in the same
// transaction, so there is no moment where the membership is off and a
// credential still works, nor one where the credentials are gone and the
// change was rolled back.
//
// revoked is how many live refresh tokens a deactivation revoked.
func (s *Service) SetMemberStatus(ctx context.Context, orgID, actorID, userID string, active bool) (before, after Member, revoked int, err error) {
	err = s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		if before, err = lockMember(ctx, tx, orgID, userID); err != nil {
			return err
		}
		if userID == actorID {
			return ErrSelf
		}
		if before.ScimManaged {
			return ErrScimManaged
		}
		if (before.Status == MemberActive) == active {
			after = before
			return nil
		}
		if active {
			if _, err := tx.Exec(ctx, `UPDATE organization_members SET deactivated_at = NULL
				WHERE organization_id = $1 AND user_id = $2`, orgID, userID); err != nil {
				return err
			}
		} else {
			if err := KeepOwner(ctx, tx, orgID, userID, func() error {
				_, err := tx.Exec(ctx, `UPDATE organization_members SET deactivated_at = now()
					WHERE organization_id = $1 AND user_id = $2`, orgID, userID)
				return err
			}); err != nil {
				return err
			}
			if revoked, err = revokeEverything(ctx, tx, orgID, userID, reasonDeactivated); err != nil {
				return err
			}
		}
		after, err = readMember(ctx, tx, orgID, userID)
		return err
	})
	if err != nil {
		return Member{}, Member{}, 0, fmt.Errorf("set member status: %w", err)
	}
	return before, after, revoked, nil
}

// SetMemberRole replaces the organisation-wide roles an administrator gave
// a member (source manual, or invite: an invite's role is a manual grant
// made in advance) with roleID, and returns the member before and after
// the change. Bindings an identity provider made (source sso or scim) and
// bindings scoped to a server, connector or tool are left alone, which is
// why this is allowed for SCIM- and SSO-managed members too.
func (s *Service) SetMemberRole(ctx context.Context, orgID, actorID, userID, roleID string) (before, after Member, err error) {
	err = s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		if before, err = lockMember(ctx, tx, orgID, userID); err != nil {
			return err
		}
		if userID == actorID {
			return ErrSelf
		}
		// Row-level security shows the built-in roles and this
		// organisation's own, so a miss covers another tenant's role too.
		var one int
		err = tx.QueryRow(ctx, `SELECT 1 FROM roles WHERE id = $1`, roleID).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSuchRole
		}
		if err != nil {
			return err
		}
		if grantedOrgRole(before) == roleID {
			after = before
			return nil
		}
		if err := KeepOwner(ctx, tx, orgID, userID, func() error {
			if _, err := tx.Exec(ctx, `DELETE FROM role_bindings
				WHERE organization_id = $1 AND principal_kind = 'user' AND principal_id = $2
				  AND scope_kind = 'org' AND source IN ('manual', 'invite')`, orgID, userID); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO role_bindings
				(id, organization_id, principal_kind, principal_id, role_id, scope_kind, source, created_by)
				VALUES ($1, $2, 'user', $3, $4, 'org', 'manual', $5)`, s.NewID(), orgID, userID, roleID, actorID)
			return err
		}); err != nil {
			return err
		}
		after, err = readMember(ctx, tx, orgID, userID)
		return err
	})
	if err != nil {
		return Member{}, Member{}, fmt.Errorf("set member role: %w", err)
	}
	return before, after, nil
}

// RemoveMember removes a member and their role bindings from the
// organisation and returns them as they were. The user record stays: they
// may belong to other organisations, and the audit trail names them.
func (s *Service) RemoveMember(ctx context.Context, orgID, actorID, userID string) (Member, error) {
	var before Member
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		if before, err = lockMember(ctx, tx, orgID, userID); err != nil {
			return err
		}
		if userID == actorID {
			return ErrSelf
		}
		if before.ScimManaged {
			return ErrScimManaged
		}
		if err := KeepOwner(ctx, tx, orgID, userID, func() error {
			if _, err := tx.Exec(ctx, `DELETE FROM role_bindings
				WHERE organization_id = $1 AND principal_kind = 'user' AND principal_id = $2`, orgID, userID); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `DELETE FROM organization_members
				WHERE organization_id = $1 AND user_id = $2`, orgID, userID)
			return err
		}); err != nil {
			return err
		}
		_, err = revokeEverything(ctx, tx, orgID, userID, reasonRemoved)
		return err
	})
	if err != nil {
		return Member{}, fmt.Errorf("remove member: %w", err)
	}
	return before, nil
}

// --- helpers ---------------------------------------------------------------

func scanMember(row pgx.Row) (Member, error) {
	var (
		m                                              Member
		deactivated, sso, password                     bool
		roleIDs, names, bindingIDs, sources, scopeKind []string
	)
	if err := row.Scan(&m.UserID, &m.Email, &m.Name, &deactivated, &m.JoinedAt, &m.ScimManaged, &sso, &password,
		&m.LastSignInAt, &roleIDs, &names, &bindingIDs, &sources, &scopeKind); err != nil {
		return Member{}, err
	}
	m.Status = MemberActive
	if deactivated {
		m.Status = MemberDeactivated
	}
	switch {
	case m.ScimManaged:
		m.Source = SourceSCIM
	case sso || !password:
		// Without a password the only way in is an identity provider,
		// even when the link to it belongs to another organisation.
		m.Source = SourceSSO
	default:
		m.Source = SourcePassword
	}
	m.Roles = make([]MemberRole, len(roleIDs))
	for i := range roleIDs {
		m.Roles[i] = MemberRole{RoleID: roleIDs[i], RoleName: names[i], BindingID: bindingIDs[i],
			Source: sources[i], ScopeKind: scopeKind[i]}
	}
	return m, nil
}

func readMember(ctx context.Context, tx pgx.Tx, orgID, userID string) (Member, error) {
	m, err := scanMember(tx.QueryRow(ctx, memberSelect+` AND m.user_id = $2`, orgID, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Member{}, ErrNotMember
	}
	return m, err
}

// lockMember takes the organisation's row lock and reads the member.
func lockMember(ctx context.Context, tx pgx.Tx, orgID, userID string) (Member, error) {
	err := LockOrganization(ctx, tx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Member{}, ErrNotMember
	}
	if err != nil {
		return Member{}, err
	}
	return readMember(ctx, tx, orgID, userID)
}

// LockOrganization takes the organisation's row lock inside tx, which must
// be a tenant transaction for orgID. Every change that can take away an
// owner (a member's status or role, their removal, a role binding deleted
// through the roles API) queues behind it, so two administrators each
// removing one of the last two owners cannot both see the other one still
// there. It returns an error wrapping pgx.ErrNoRows when the organisation
// does not exist.
func LockOrganization(ctx context.Context, tx pgx.Tx, orgID string) error {
	var one int
	if err := tx.QueryRow(ctx, `SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE`, orgID).Scan(&one); err != nil {
		return fmt.Errorf("lock organisation: %w", err)
	}
	return nil
}

// KeepOwner runs change inside tx and refuses it with ErrLastOwner if it
// left the organisation with no active owner: a member who is not
// deactivated and holds the owner role organisation-wide through an
// unexpired binding. It only asks when userID was such an owner to begin
// with, so an organisation that somehow has none can still be repaired.
//
// The caller must hold LockOrganization for orgID in the same transaction;
// without it two concurrent changes can each leave the other's owner as
// the last one and both commit.
func KeepOwner(ctx context.Context, tx pgx.Tx, orgID, userID string, change func() error) error {
	var wasOwner bool
	if err := tx.QueryRow(ctx, activeOwnersSelect+`
SELECT EXISTS (SELECT 1 FROM owners WHERE principal_id = $2)`, orgID, userID).Scan(&wasOwner); err != nil {
		return fmt.Errorf("read owners: %w", err)
	}
	if err := change(); err != nil {
		return err
	}
	if !wasOwner {
		return nil
	}
	var owners int
	if err := tx.QueryRow(ctx, activeOwnersSelect+`
SELECT count(DISTINCT principal_id) FROM owners`, orgID).Scan(&owners); err != nil {
		return fmt.Errorf("count owners: %w", err)
	}
	if owners == 0 {
		return ErrLastOwner
	}
	return nil
}

// grantedOrgRole returns the one role a member holds through
// organisation-wide bindings an administrator made, or "" when they hold
// none or several.
func grantedOrgRole(m Member) string {
	var ids []string
	for _, r := range m.Roles {
		if grantedSource(r.Source) && r.ScopeKind == "org" && !slices.Contains(ids, r.RoleID) {
			ids = append(ids, r.RoleID)
		}
	}
	if len(ids) != 1 {
		return ""
	}
	return ids[0]
}

// grantedSource reports whether a binding with this source is one an
// administrator made, directly or through an invite, and so one
// SetMemberRole replaces; sso and scim bindings belong to the identity
// provider. SetMemberRole's DELETE spells the same list.
func grantedSource(source string) bool {
	return source == "manual" || source == "invite"
}

// revokeEverything is RevokeEverything inside the caller's transaction, so
// the credentials end together with the change that ended the membership.
// auth_principal_end is SECURITY DEFINER and ends the user's sessions in
// every organisation, with the refresh tokens they granted, as SCIM
// deprovisioning does. It returns how many live refresh tokens it revoked.
func revokeEverything(ctx context.Context, tx pgx.Tx, orgID, userID, reason string) (int, error) {
	var n int
	if err := tx.QueryRow(ctx, `SELECT auth_principal_end($1,$2,$3)`, orgID, userID, reason).Scan(&n); err != nil {
		return 0, fmt.Errorf("revoke credentials: %w", err)
	}
	return n, nil
}
