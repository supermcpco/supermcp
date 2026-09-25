// Package identity owns users, organisations, passwords and sessions.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// Errors.
var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrLocked             = errors.New("too many failed attempts; try again later")
	ErrDisabled           = errors.New("account is disabled")
	ErrRegistrationClosed = errors.New("registration is closed")
	ErrEmailTaken         = errors.New("an account with this email already exists")
	ErrSessionInvalid     = errors.New("session is invalid or expired")
	// ErrNotInOrganization is SwitchOrg's refusal: the person does not
	// belong to the organisation they asked for, or it does not exist.
	ErrNotInOrganization = errors.New("you are not a member of that organisation")
)

// Config tunes the service.
type Config struct {
	OpenRegistration bool          // allow self-registration after the first user
	SessionIdle      time.Duration // default 12h
	SessionAbsolute  time.Duration // default 30d
	LockoutThreshold int           // failures before lock, default 10
	LockoutWindow    time.Duration // default 15m
}

func (c Config) defaults() Config {
	if c.SessionIdle == 0 {
		c.SessionIdle = 12 * time.Hour
	}
	if c.SessionAbsolute == 0 {
		c.SessionAbsolute = 30 * 24 * time.Hour
	}
	if c.LockoutThreshold == 0 {
		c.LockoutThreshold = 10
	}
	if c.LockoutWindow == 0 {
		c.LockoutWindow = 15 * time.Minute
	}
	return c
}

// Service is the identity service.
type Service struct {
	DB    *tenant.DB
	Cfg   Config
	Authz *authz.Evaluator
	NewID func() string
	now   func() time.Time

	// fresh remembers, per user and workspace, when a password was last
	// found to be within its maximum age. See PasswordExpired.
	fresh   map[string]time.Time
	freshMu sync.Mutex
}

// New builds the service.
func New(db *tenant.DB, cfg Config, az *authz.Evaluator, newID func() string) *Service {
	return &Service{DB: db, Cfg: cfg.defaults(), Authz: az, NewID: newID, now: time.Now, fresh: map[string]time.Time{}}
}

// User is a user record.
type User struct {
	ID         string
	Email      string
	Name       string
	DisabledAt *time.Time
}

// Org is an organisation.
type Org struct {
	ID   string
	Slug string
	Name string
}

// Session is a server-side session.
type Session struct {
	// ID is what the database holds and what everything else names a
	// session by. It is the digest of the secret, never the secret.
	ID string
	// Secret is the value that goes in the cookie, and it exists only on
	// the session that was just created. A session read back from the
	// database cannot produce it, which is the point: read access to the
	// table is not enough to impersonate anybody.
	Secret            string
	UserID            string
	OrgID             string
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	MFAVerifiedAt     *time.Time
	// AuthMethod is how the session was signed in: password, sso or saml.
	AuthMethod string
	// AuthProviderID is the single sign-on provider the session came
	// from, and empty for a password sign-in.
	AuthProviderID string
	// AuthenticatedAt is when the holder last proved who they are: at
	// sign-in, and again at each re-authentication. Zero when nobody
	// vouched for the time, as for a provider that does not say.
	AuthenticatedAt time.Time
	LastSeenAt      time.Time
}

var reEmail = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
var reSlug = regexp.MustCompile(`[^a-z0-9]+`)

// RegisterInput creates the first user (and organisation) or, when open
// registration is on, an additional user with their own organisation.
type RegisterInput struct {
	Email, Name, Password, OrgName string
}

// Unclaimed reports whether this instance has no users yet. The first
// registration is always allowed, whatever the setting says, so the sign-in
// screen has to be able to ask.
func (s *Service) Unclaimed(ctx context.Context) bool {
	var count int64
	if err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT auth_user_count()").Scan(&count)
	}); err != nil {
		return false // a failure to look is not an invitation
	}
	return count == 0
}

// Register creates a user and an organisation they own.
func (s *Service) Register(ctx context.Context, in RegisterInput) (*User, *Org, error) {
	in.Email = strings.TrimSpace(strings.ToLower(in.Email))
	if !reEmail.MatchString(in.Email) {
		return nil, nil, errors.New("invalid email address")
	}
	if err := CheckPolicy(in.Password, DefaultPolicy); err != nil {
		return nil, nil, err
	}
	var count int64
	if err := s.DB.Pre(ctx, func(tx pgx.Tx) error { return tx.QueryRow(ctx, "SELECT auth_user_count()").Scan(&count) }); err != nil {
		return nil, nil, err
	}
	if count > 0 && !s.Cfg.OpenRegistration {
		return nil, nil, ErrRegistrationClosed
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		return nil, nil, err
	}
	if in.OrgName == "" {
		in.OrgName = in.Name + "'s workspace"
		if in.Name == "" {
			in.OrgName = "Workspace"
		}
	}
	u := &User{ID: s.NewID(), Email: in.Email, Name: in.Name}
	o := &Org{ID: s.NewID(), Name: in.OrgName, Slug: slugify(in.OrgName) + "-" + strings.ToLower(u.ID[len(u.ID)-6:])}
	err = s.DB.Pre(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT auth_register($1,$2,$3,$4,$5,$6,$7)", u.ID, u.Email, u.Name, hash, o.ID, o.Slug, o.Name)
		return err
	})
	if err != nil {
		if strings.Contains(err.Error(), "users_email_lower_idx") {
			return nil, nil, ErrEmailTaken
		}
		return nil, nil, err
	}
	// Count the first password against the reuse policy as well.
	_ = s.DB.Pre(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT auth_password_record($1,$2)", u.ID, hash)
		return err
	})
	// The creator owns the organisation.
	err = s.DB.Tx(tenant.WithOrg(ctx, o.ID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id, created_by) VALUES ($1,$2,'user',$3,'role_owner',$3)`, s.NewID(), o.ID, u.ID)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return u, o, nil
}

func slugify(s string) string {
	s = strings.Trim(reSlug.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 40 {
		s = s[:40]
	}
	if s == "" {
		s = "org"
	}
	return s
}

// Login verifies a password with lockout and timing protection.
func (s *Service) Login(ctx context.Context, email, password, ip string) (*User, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if locked, err := s.locked(ctx, "user:"+email, "ip:"+ip); err != nil {
		return nil, err
	} else if locked {
		return nil, ErrLocked
	}
	var u User
	var hash *string
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT id, email, name, password_hash, disabled_at FROM auth_user_by_email($1)", email).
			Scan(&u.ID, &u.Email, &u.Name, &hash, &u.DisabledAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		_, _, _ = VerifyPassword(dummyHash, password) // burn the same time
		s.failed(ctx, "user:"+email, "ip:"+ip)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	stored := ""
	if hash != nil {
		stored = *hash
	}
	ok, upgrade, err := VerifyPassword(stored, password)
	if err != nil {
		return nil, err
	}
	if !ok {
		s.failed(ctx, "user:"+email, "ip:"+ip)
		return nil, ErrInvalidCredentials
	}
	if u.DisabledAt != nil {
		return nil, ErrDisabled
	}
	s.clear(ctx, "user:"+email, "ip:"+ip)
	if upgrade {
		if nh, err := HashPassword(password); err == nil {
			_ = s.DB.Bypass(ctx, "password-hash-upgrade", func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, "UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1", u.ID, nh)
				return err
			})
		}
	}
	return &u, nil
}

// Orgs lists the organisations a user belongs to.
func (s *Service) Orgs(ctx context.Context, userID string) ([]Org, error) {
	var out []Org
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT organization_id, slug, name FROM auth_user_orgs($1) ORDER BY name", userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o Org
			if err := rows.Scan(&o.ID, &o.Slug, &o.Name); err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

// --- lockout --------------------------------------------------------------

func (s *Service) locked(ctx context.Context, keys ...string) (bool, error) {
	locked := false
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		for _, k := range keys {
			var until *time.Time
			err := tx.QueryRow(ctx, "SELECT locked_until FROM login_lockouts WHERE key = $1", k).Scan(&until)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if until != nil && until.After(s.now()) {
				locked = true
			}
		}
		return nil
	})
	return locked, err
}

func (s *Service) failed(ctx context.Context, keys ...string) {
	_ = s.DB.Pre(ctx, func(tx pgx.Tx) error {
		for _, k := range keys {
			threshold := s.Cfg.LockoutThreshold
			if strings.HasPrefix(k, "ip:") {
				threshold *= 10
			}
			_, err := tx.Exec(ctx, `
INSERT INTO login_lockouts (key, failures, updated_at) VALUES ($1, 1, now())
ON CONFLICT (key) DO UPDATE SET
  failures = CASE WHEN login_lockouts.updated_at < now() - $2::interval THEN 1 ELSE login_lockouts.failures + 1 END,
  locked_until = CASE WHEN (CASE WHEN login_lockouts.updated_at < now() - $2::interval THEN 1 ELSE login_lockouts.failures + 1 END) >= $3
                      THEN now() + LEAST($2::interval * power(2, GREATEST(0, login_lockouts.failures + 1 - $3)), interval '24 hours') END,
  updated_at = now()`, k, s.Cfg.LockoutWindow.String(), threshold)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Service) clear(ctx context.Context, keys ...string) {
	_ = s.DB.Pre(ctx, func(tx pgx.Tx) error {
		for _, k := range keys {
			if _, err := tx.Exec(ctx, "UPDATE login_lockouts SET failures = 0, locked_until = NULL, updated_at = now() WHERE key = $1", k); err != nil {
				return err
			}
		}
		return nil
	})
}

// --- sessions -------------------------------------------------------------

// CreateSession opens a session for a user in an organisation. provider
// names the single sign-on provider for an sso or saml sign-in and is
// empty for a password one. authenticatedAt is when the person proved who
// they are: now for a password, and for single sign-on what the provider
// said. The zero time records a sign-in nobody vouched the time of, which
// is never fresh.
func (s *Service) CreateSession(ctx context.Context, userID, orgID, method, provider string, authenticatedAt time.Time, ip, ua string) (*Session, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	now := s.now()
	secret := base64.RawURLEncoding.EncodeToString(raw)
	sess := &Session{ID: SessionKey(secret), Secret: secret, UserID: userID, OrgID: orgID,
		IdleExpiresAt: now.Add(s.Cfg.SessionIdle), AbsoluteExpiresAt: now.Add(s.Cfg.SessionAbsolute), AuthMethod: method,
		AuthProviderID: provider, AuthenticatedAt: authenticatedAt, LastSeenAt: now}
	var at *time.Time
	if !authenticatedAt.IsZero() {
		at = &authenticatedAt
	}
	var addr *netip.Addr
	if a, err := netip.ParseAddr(ip); err == nil {
		addr = &a
	}
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT auth_session_open($1,$2,NULLIF($3,''),$4,$5,$6,NULLIF($7,''),$8,$9,$10)",
			sess.ID, userID, orgID, sess.IdleExpiresAt, sess.AbsoluteExpiresAt, method, provider, at, addr, ua)
		return err
	})
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// PruneSessions removes the sessions nobody can use any more. The grace
// period keeps a revoked session readable for a while, because "your
// session was ended at 14:02" is a better answer to a support question
// than a row that is not there. A session a live refresh token still
// names stays: a token whose session is not on record is refused, and an
// expired session's tokens are meant to outlive it.
func (s *Service) PruneSessions(ctx context.Context) error {
	return s.DB.Bypass(ctx, "session-prune", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM sessions
			WHERE (absolute_expires_at < now() - interval '7 days'
			    OR idle_expires_at < now() - interval '7 days'
			    OR revoked_at < now() - interval '7 days')
			  AND NOT EXISTS (SELECT 1 FROM oauth_refresh_tokens r
			                  WHERE r.session_id = sessions.id AND r.revoked_at IS NULL
			                    AND r.consumed_at IS NULL AND r.expires_at > now())`)
		return err
	})
}

// SessionKey is the identifier stored for a session secret. Cookies carry
// the secret; the table carries this, the way API keys and refresh tokens
// are already held, so that a reader of the database cannot take over a
// live session.
func SessionKey(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// LoadSession validates a session id and refreshes its idle timer at most
// once a minute. The id is what SessionKey returns, not what the cookie
// carries.
func (s *Service) LoadSession(ctx context.Context, id string) (*Session, error) {
	if id == "" {
		return nil, ErrSessionInvalid
	}
	var sess Session
	var org *string
	var revoked *time.Time
	var provider *string
	var authenticated *time.Time
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, user_id, organization_id, idle_expires_at, absolute_expires_at, mfa_verified_at,
				auth_method, revoked_at, last_seen_at, authenticated_at, auth_provider_id FROM auth_session_load($1)`, id).
			Scan(&sess.ID, &sess.UserID, &org, &sess.IdleExpiresAt, &sess.AbsoluteExpiresAt, &sess.MFAVerifiedAt,
				&sess.AuthMethod, &revoked, &sess.LastSeenAt, &authenticated, &provider)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, err
	}
	if org != nil {
		sess.OrgID = *org
	}
	if provider != nil {
		sess.AuthProviderID = *provider
	}
	if authenticated != nil {
		sess.AuthenticatedAt = *authenticated
	}
	now := s.now()
	if revoked != nil || now.After(sess.IdleExpiresAt) || now.After(sess.AbsoluteExpiresAt) {
		return nil, ErrSessionInvalid
	}
	if now.Sub(sess.LastSeenAt) > time.Minute {
		sess.IdleExpiresAt = now.Add(s.Cfg.SessionIdle)
		if sess.IdleExpiresAt.After(sess.AbsoluteExpiresAt) {
			sess.IdleExpiresAt = sess.AbsoluteExpiresAt
		}
		_ = s.DB.Pre(ctx, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "SELECT auth_session_touch($1,$2,NULL)", sess.ID, sess.IdleExpiresAt)
			return err
		})
	}
	return &sess, nil
}

// SwitchOrg changes the session's active organisation after checking
// membership.
func (s *Service) SwitchOrg(ctx context.Context, sess *Session, orgID string) error {
	orgs, err := s.Orgs(ctx, sess.UserID)
	if err != nil {
		return err
	}
	for _, o := range orgs {
		if o.ID == orgID {
			return s.DB.Pre(ctx, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, "SELECT auth_session_touch($1,$2,$3)", sess.ID, sess.IdleExpiresAt, orgID)
				return err
			})
		}
	}
	return ErrNotInOrganization
}

// RevokeSession ends a session and the refresh tokens it granted, and
// returns how many live refresh tokens that revoked.
func (s *Service) RevokeSession(ctx context.Context, id, reason string) (int, error) {
	var n int
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT auth_session_end($1,$2)", id, reason).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("end session: %w", err)
	}
	return n, nil
}

// ReplaceSession ends a session that a re-authentication replaced with
// another for the same person. The refresh tokens the old session
// consented to move to the new one instead of ending with it.
func (s *Service) ReplaceSession(ctx context.Context, oldID, newID, reason string) error {
	return s.DB.Pre(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT auth_session_replace($1,$2,$3)", oldID, newID, reason)
		return err
	})
}

// SessionEnded reports whether the session with this public id was
// ended. An expired session was not. One no longer on record was: the
// pruner keeps any session a live refresh token still names.
func (s *Service) SessionEnded(ctx context.Context, publicID string) (bool, error) {
	var ended bool
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT auth_session_ended($1)", publicID).Scan(&ended)
	})
	if err != nil {
		return false, fmt.Errorf("read session: %w", err)
	}
	return ended, nil
}

// Principal builds the request principal from a session.
func (s *Service) Principal(sess *Session, email string) *authz.Principal {
	return &authz.Principal{Kind: authz.KindUser, ID: sess.UserID, OrgID: sess.OrgID, SessionID: sess.ID, AuthMethod: "session",
		MFA: sess.MFAVerifiedAt != nil, Email: email,
		SignIn: authz.SignIn{At: sess.AuthenticatedAt, Method: sess.AuthMethod, ProviderID: sess.AuthProviderID}}
}

// UserByID loads a user visible in the current tenant.
func (s *Service) UserByID(ctx context.Context, orgID, id string) (*User, error) {
	var u User
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT id, email, name, disabled_at FROM users WHERE id = $1", id).Scan(&u.ID, &u.Email, &u.Name, &u.DisabledAt)
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// MarkVerified records that the identity provider verified this person,
// including whatever second factor it enforces. We issue no factor of our
// own, so this is what a policy requiring one reads.
func (s *Service) MarkVerified(ctx context.Context, sessionID string) error {
	return s.DB.Pre(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT auth_session_verify($1)", sessionID)
		return err
	})
}

// RevokeOtherSessions ends every session of a user except the one given,
// with the refresh tokens they granted, and returns how many live refresh
// tokens that revoked.
func (s *Service) RevokeOtherSessions(ctx context.Context, userID, keepSessionID, reason string) (int, error) {
	var n int
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT auth_session_end_others($1,$2,$3)", userID, keepSessionID, reason).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("end other sessions: %w", err)
	}
	return n, nil
}
