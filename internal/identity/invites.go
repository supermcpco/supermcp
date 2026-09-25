package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/tenant"
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
	// ErrInviteSignInFirst refuses an anonymous acceptance for an address
	// that already has an account: accounts are never merged on a request
	// that has not proved it owns one.
	ErrInviteSignInFirst = errors.New("an account with this email address already exists; sign in first, then open the link again")
	// ErrInviteSignedIn refuses a password sent by a caller who is already
	// signed in; their existing account is the one that joins.
	ErrInviteSignedIn = errors.New("you are signed in; accept the invitation without a password")
	// ErrAlreadyMember refuses an invite for someone who already belongs to
	// the organisation, deactivated or not.
	ErrAlreadyMember = errors.New("this person is already a member of the organisation; change their role or reactivate them instead")
	// ErrInviteRole refuses a role the organisation cannot use.
	ErrInviteRole = errors.New("no such role")
	// ErrInviteRoleTooBroad refuses an invite to a role that allows
	// everything from somebody who does not hold such a role themselves.
	ErrInviteRoleTooBroad = errors.New("only someone who can do everything in the organisation can invite to a role that allows everything")
	// ErrInviteEmail refuses an address that is not one.
	ErrInviteEmail = errors.New("invalid email address")
	// ErrInviteTTL refuses a lifetime outside what an invite may have.
	ErrInviteTTL = errors.New("an invitation lasts between one and 30 days")
	// ErrInviteLimit refuses a new invite while too many are open.
	ErrInviteLimit = errors.New("too many open invitations; revoke some or wait for them to be accepted")
)

// InviteStatus values.
const (
	InvitePending  = "pending"
	InviteAccepted = "accepted"
	InviteRevoked  = "revoked"
	InviteExpired  = "expired"
)

// Invite lifetimes and limits.
const (
	// DefaultInviteTTL is how long a link works when the administrator
	// does not say.
	DefaultInviteTTL = 7 * 24 * time.Hour
	// MaxInviteTTL is the longest a link may work.
	MaxInviteTTL = 30 * 24 * time.Hour
	// MaxOpenInvites is how many pending invites an organisation may have.
	MaxOpenInvites = 100

	// inviteTokenBytes is the entropy of a token.
	inviteTokenBytes = 32
	// inviteListLimit bounds the list; pending invites are capped well
	// below it, so only old history is cut.
	inviteListLimit = 500
	// inviteActiveIndex is the partial unique index that allows one open
	// invite per address per organisation.
	inviteActiveIndex = "org_invites_active_idx"
)

// Invite is an invitation as an administrator sees it. It never carries
// the token.
type Invite struct {
	ID        string
	OrgID     string
	Email     string
	RoleID    string
	RoleName  string
	InvitedBy string
	// InvitedByName is the inviter's name, or address when they have
	// none; empty once they are no longer a member.
	InvitedByName string
	Status        string // InvitePending, InviteAccepted, InviteRevoked or InviteExpired
	ExpiresAt     time.Time
	AcceptedAt    *time.Time
	RevokedAt     *time.Time
	CreatedAt     time.Time
}

// InviteInput is what an administrator asks for.
type InviteInput struct {
	Email  string
	RoleID string
	// TTL is how long the link works; zero means DefaultInviteTTL.
	TTL time.Duration
	// ActorHoldsAll says the administrator holds the wildcard permission,
	// which inviting to a role that grants it requires. The caller decides
	// it with the authorisation evaluator, which knows how the actor
	// authenticated (a scoped key never holds it).
	ActorHoldsAll bool
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
	// PasswordPolicy is the organisation's policy for the password of the
	// account accepting creates. Set only when RegistrationRequired.
	PasswordPolicy *PasswordPolicy
}

// AcceptInput is what an anonymous caller sends to create their account.
// A signed-in caller sends neither field.
type AcceptInput struct {
	Name     string
	Password string
}

// Accepted is the outcome of accepting an invite.
type Accepted struct {
	User User
	Org  Org // ID and Name; the slug is not read
	// Created is true when accepting made a new account.
	Created   bool
	InviteID  string
	RoleID    string
	RoleName  string
	InvitedBy string
}

// pendingInvite is a row auth_invite_by_token returned.
type pendingInvite struct {
	ID, OrgID, OrgName, Email, RoleID, RoleName string
	ExpiresAt                                   time.Time
}

// CreateInvite opens an invite and returns it with the token. The token is
// not stored and cannot be read back. An expired invite for the same
// address is revoked first, because it still holds the address's slot.
func (s *Service) CreateInvite(ctx context.Context, orgID, actorID string, in InviteInput) (Invite, string, error) {
	email := strings.TrimSpace(strings.ToLower(in.Email))
	if !reEmail.MatchString(email) {
		return Invite{}, "", ErrInviteEmail
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = DefaultInviteTTL
	}
	if ttl < 0 || ttl > MaxInviteTTL {
		return Invite{}, "", ErrInviteTTL
	}
	token, digest, err := newInviteToken()
	if err != nil {
		return Invite{}, "", err
	}
	now := s.now()
	id := s.NewID()
	var inv Invite
	err = s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var perms []string
		err := tx.QueryRow(ctx, `SELECT permissions FROM roles WHERE id = $1`, in.RoleID).Scan(&perms)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInviteRole
		}
		if err != nil {
			return fmt.Errorf("read role: %w", err)
		}
		if slices.Contains(perms, string(authz.Wildcard)) && !in.ActorHoldsAll {
			return ErrInviteRoleTooBroad
		}
		var member bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organization_members m JOIN users u ON u.id = m.user_id
			WHERE m.organization_id = $1 AND u.email_lower = $2)`, orgID, email).Scan(&member); err != nil {
			return fmt.Errorf("check membership: %w", err)
		}
		if member {
			return ErrAlreadyMember
		}
		// Serialise invite creation in the organisation, so the cap below
		// is exact rather than approximate under concurrent requests.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('org_invites:' || $1))`, orgID); err != nil {
			return fmt.Errorf("lock invites: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE org_invites SET revoked_at = now()
			WHERE email_lower = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at <= now()`, email); err != nil {
			return fmt.Errorf("retire expired invite: %w", err)
		}
		var open int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM org_invites
			WHERE accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()`).Scan(&open); err != nil {
			return fmt.Errorf("count invites: %w", err)
		}
		if open >= MaxOpenInvites {
			return ErrInviteLimit
		}
		_, err = tx.Exec(ctx, `INSERT INTO org_invites (id, organization_id, email, role_id, token_hash, invited_by, expires_at)
			VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7)`,
			id, orgID, email, in.RoleID, digest, actorID, now.Add(ttl))
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == inviteActiveIndex {
			return ErrInviteExists
		}
		if err != nil {
			return fmt.Errorf("insert invite: %w", err)
		}
		inv, err = scanInvite(tx.QueryRow(ctx, inviteSelect+` WHERE i.id = $1`, id), now)
		return err
	})
	if err != nil {
		return Invite{}, "", err
	}
	return inv, token, nil
}

// ListInvites returns the organisation's invites, newest first, at most
// inviteListLimit of them.
func (s *Service) ListInvites(ctx context.Context, orgID string) ([]Invite, error) {
	now := s.now()
	out := make([]Invite, 0, 16)
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, inviteSelect+` ORDER BY i.created_at DESC, i.id DESC LIMIT $1`, inviteListLimit)
		if err != nil {
			return fmt.Errorf("list invites: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			inv, err := scanInvite(rows, now)
			if err != nil {
				return err
			}
			out = append(out, inv)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeInvite revokes an invite that has not been accepted or revoked,
// expired or not, and returns it. Anything else, including another
// organisation's invite, is ErrInviteInvalid.
func (s *Service) RevokeInvite(ctx context.Context, orgID, id string) (Invite, error) {
	var inv Invite
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE org_invites SET revoked_at = now()
			WHERE id = $1 AND accepted_at IS NULL AND revoked_at IS NULL`, id)
		if err != nil {
			return fmt.Errorf("revoke invite: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrInviteInvalid
		}
		inv, err = scanInvite(tx.QueryRow(ctx, inviteSelect+` WHERE i.id = $1`, id), s.now())
		return err
	})
	if err != nil {
		return Invite{}, err
	}
	return inv, nil
}

// LookupInvite resolves a token to what its holder may see. It needs no
// session. Every failure to find the invite is ErrInviteInvalid, and each
// one counts against ip, which is locked out (ErrLocked) after as many
// failures as a sign-in would be.
func (s *Service) LookupInvite(ctx context.Context, token, ip string) (*InviteLookup, error) {
	inv, err := s.pendingInvite(ctx, token, ip)
	if err != nil {
		return nil, err
	}
	exists, err := s.emailTaken(ctx, inv.Email)
	if err != nil {
		return nil, err
	}
	out := &InviteLookup{OrgID: inv.OrgID, OrgName: inv.OrgName, Email: inv.Email, RoleName: inv.RoleName,
		ExpiresAt: inv.ExpiresAt, RegistrationRequired: !exists}
	if !exists {
		policy, err := s.LoadPolicy(ctx, inv.OrgID)
		if err != nil {
			return nil, err
		}
		out.PasswordPolicy = &policy
	}
	return out, nil
}

// AcceptInvite consumes the invite for token. signedInID is the caller's
// user id when they have a session, "" otherwise. A signed-in caller must
// be the invited address and sends no password; an anonymous one must
// send a password that meets the organisation's policy, and gets a new
// account whatever the open-registration setting, unless the address
// already has one (ErrInviteSignInFirst).
func (s *Service) AcceptInvite(ctx context.Context, token, ip, signedInID string, in AcceptInput) (*Accepted, error) {
	inv, err := s.pendingInvite(ctx, token, ip)
	if err != nil {
		return nil, err
	}
	digest, _ := inviteDigest(token) // pendingInvite has checked the shape
	out := &Accepted{Org: Org{ID: inv.OrgID, Name: inv.OrgName}, InviteID: inv.ID, RoleID: inv.RoleID, RoleName: inv.RoleName}

	var existing, newID, email, hash *string
	name := strings.TrimSpace(in.Name)
	if signedInID != "" {
		if in.Password != "" {
			return nil, ErrInviteSignedIn
		}
		u, err := s.userByID(ctx, signedInID)
		if err != nil {
			return nil, err
		}
		if u.DisabledAt != nil {
			return nil, ErrDisabled
		}
		if !strings.EqualFold(u.Email, inv.Email) {
			return nil, ErrInviteEmailMismatch
		}
		out.User = *u
		existing = &u.ID
	} else {
		taken, err := s.emailTaken(ctx, inv.Email)
		if err != nil {
			return nil, err
		}
		if taken {
			return nil, ErrInviteSignInFirst
		}
		policy, err := s.LoadPolicy(ctx, inv.OrgID)
		if err != nil {
			return nil, err
		}
		if err := CheckPolicy(in.Password, policy); err != nil {
			return nil, err
		}
		h, err := HashPassword(in.Password)
		if err != nil {
			return nil, err
		}
		lower := strings.ToLower(inv.Email)
		out.User = User{ID: s.NewID(), Email: lower, Name: name}
		out.Created = true
		newID, email, hash = &out.User.ID, &lower, &h
	}

	var userID, orgID string
	err = s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT user_id, organization_id FROM auth_invite_accept($1, $2, $3, $4, $5, $6, $7)`,
			digest, existing, newID, email, name, hash, s.NewID()).Scan(&userID, &orgID)
	})
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Accepted, revoked or expired since the lookup above.
		return nil, ErrInviteInvalid
	case errors.As(err, &pgErr) && pgErr.Code == pgInsufficientPrivilege:
		return nil, ErrInviteEmailMismatch
	case errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation:
		// Somebody registered the address since the check above.
		return nil, ErrInviteSignInFirst
	case err != nil:
		return nil, fmt.Errorf("accept invite: %w", err)
	}
	if err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var by *string
		err := tx.QueryRow(ctx, `SELECT invited_by FROM org_invites WHERE id = $1`, inv.ID).Scan(&by)
		if by != nil {
			out.InvitedBy = *by
		}
		return err
	}); err != nil {
		return nil, fmt.Errorf("read accepted invite: %w", err)
	}
	return out, nil
}

// --- helpers ---------------------------------------------------------------

// SQLSTATEs the invite functions raise.
const (
	pgUniqueViolation       = "23505"
	pgInsufficientPrivilege = "42501"
)

// inviteSelect reads invites with their role's name and the inviter's
// display name. Row-level security shows the inviter only while they are
// a member, the way the tool history names an editor.
const inviteSelect = `SELECT i.id, i.organization_id, i.email, i.role_id, r.name, COALESCE(i.invited_by, ''),
	COALESCE(NULLIF(u.name, ''), u.email, ''), i.expires_at, i.accepted_at, i.revoked_at, i.created_at
	FROM org_invites i JOIN roles r ON r.id = i.role_id LEFT JOIN users u ON u.id = i.invited_by`

func scanInvite(row pgx.Row, now time.Time) (Invite, error) {
	var inv Invite
	if err := row.Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.RoleID, &inv.RoleName, &inv.InvitedBy, &inv.InvitedByName,
		&inv.ExpiresAt, &inv.AcceptedAt, &inv.RevokedAt, &inv.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Invite{}, ErrInviteInvalid
		}
		return Invite{}, fmt.Errorf("scan invite: %w", err)
	}
	inv.Status = inviteStatus(inv.AcceptedAt, inv.RevokedAt, inv.ExpiresAt, now)
	return inv, nil
}

// inviteStatus derives what an administrator is told about an invite.
// Acceptance and revocation are final and win over expiry.
func inviteStatus(acceptedAt, revokedAt *time.Time, expiresAt, now time.Time) string {
	switch {
	case acceptedAt != nil:
		return InviteAccepted
	case revokedAt != nil:
		return InviteRevoked
	case !now.Before(expiresAt):
		return InviteExpired
	}
	return InvitePending
}

// newInviteToken returns a fresh token and the digest that is stored for
// it, in the way API keys are held (mcpauth.Generate).
func newInviteToken() (token string, digest []byte, err error) {
	raw := make([]byte, inviteTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("invite token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

// inviteDigest returns the stored digest for a presented token, or false
// when it cannot be a token this server issued.
func inviteDigest(token string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != inviteTokenBytes {
		return nil, false
	}
	sum := sha256.Sum256([]byte(token))
	return sum[:], true
}

// pendingInvite finds the pending invite for token, counting a miss
// against ip. The comparison is digest equality in the database, so there
// is no secret compared in Go.
func (s *Service) pendingInvite(ctx context.Context, token, ip string) (pendingInvite, error) {
	key := "invite:" + ip
	if ip != "" {
		locked, err := s.locked(ctx, key)
		if err != nil {
			return pendingInvite{}, err
		}
		if locked {
			return pendingInvite{}, ErrLocked
		}
	}
	miss := func() (pendingInvite, error) {
		if ip != "" {
			s.failed(ctx, key)
		}
		return pendingInvite{}, ErrInviteInvalid
	}
	digest, ok := inviteDigest(token)
	if !ok {
		return miss()
	}
	var inv pendingInvite
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, organization_id, org_name, email, role_id, role_name, expires_at
			FROM auth_invite_by_token($1)`, digest).
			Scan(&inv.ID, &inv.OrgID, &inv.OrgName, &inv.Email, &inv.RoleID, &inv.RoleName, &inv.ExpiresAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return miss()
	}
	if err != nil {
		return pendingInvite{}, fmt.Errorf("look up invite: %w", err)
	}
	return inv, nil
}

// emailTaken reports whether any account uses email.
func (s *Service) emailTaken(ctx context.Context, email string) (bool, error) {
	var taken bool
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth_user_by_email($1))`, strings.ToLower(email)).Scan(&taken)
	})
	if err != nil {
		return false, fmt.Errorf("look up account: %w", err)
	}
	return taken, nil
}

// userByID loads a user whatever organisation, if any, the caller's
// session is in.
func (s *Service) userByID(ctx context.Context, id string) (*User, error) {
	var u User
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, email, name, disabled_at FROM auth_user_by_id($1)`, id).
			Scan(&u.ID, &u.Email, &u.Name, &u.DisabledAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	return &u, nil
}
