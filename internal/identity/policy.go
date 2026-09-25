package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/tenant"
)

// A password policy is per organisation. It is enforced where a password
// is set, not where one is used: an existing password that no longer meets
// a tightened policy still signs its owner in, and the maximum age is what
// forces the change.

// ErrPasswordReused is returned when a new password matches a recent one.
var ErrPasswordReused = errors.New("this password was used recently; choose a different one")

// ErrWrongPassword is the current password being wrong. It is distinct
// from a failed sign-in: the person is already signed in, was never asked
// for an email, and telling them "invalid email or password" describes a
// form they are not looking at.
var ErrWrongPassword = errors.New("that is not your current password")

// ErrPasswordExpired reports that the policy requires a change now.
var ErrPasswordExpired = errors.New("this password has expired and must be changed")

// LoadPolicy returns an organisation's policy, or the default when it has
// not set one. An empty org id also gives the default, which is what the
// first registration on a fresh instance uses.
func (s *Service) LoadPolicy(ctx context.Context, orgID string) (PasswordPolicy, error) {
	p := DefaultPolicy
	if orgID == "" {
		return p, nil
	}
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT min_length, require_classes, history, max_age_days
			FROM auth_password_policy($1)`, orgID).Scan(&p.MinLength, &p.RequireClasses, &p.History, &p.MaxAgeDays)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultPolicy, nil
	}
	if err != nil {
		return DefaultPolicy, err
	}
	return p, nil
}

// SetPolicy stores an organisation's policy.
func (s *Service) SetPolicy(ctx context.Context, orgID string, p PasswordPolicy) (PasswordPolicy, error) {
	if p.MinLength < 8 || p.MinLength > 256 {
		return p, fmt.Errorf("%w: the minimum length must be between 8 and 256", ErrWeakPassword)
	}
	if p.RequireClasses < 1 || p.RequireClasses > 4 {
		return p, fmt.Errorf("%w: require between 1 and 4 character classes", ErrWeakPassword)
	}
	if p.History < 0 || p.History > 24 {
		return p, fmt.Errorf("%w: keep between 0 and 24 previous passwords", ErrWeakPassword)
	}
	if p.MaxAgeDays < 0 || p.MaxAgeDays > 3650 {
		return p, fmt.Errorf("%w: the maximum age must be between 0 and 3650 days", ErrWeakPassword)
	}
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO password_policies (organization_id, min_length, require_classes, history, max_age_days)
			VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (organization_id) DO UPDATE SET min_length = EXCLUDED.min_length,
				require_classes = EXCLUDED.require_classes, history = EXCLUDED.history,
				max_age_days = EXCLUDED.max_age_days, updated_at = now()`,
			orgID, p.MinLength, p.RequireClasses, p.History, p.MaxAgeDays)
		return err
	})
	if err == nil {
		s.forgetFresh()
	}
	return p, err
}

// ChangePassword replaces a user's own password after verifying the
// current one.
//
// A wrong current password counts against the same lockout as the sign-in
// form, keyed by the account's address and the client address ip, so a
// stolen session is no better a place to guess the password from than the
// sign-in page.
func (s *Service) ChangePassword(ctx context.Context, userID, orgID, current, next, ip string) error {
	var email string
	var stored *string
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT email, password_hash FROM auth_user_by_id($1)`, userID).Scan(&email, &stored)
	})
	if err != nil {
		return err
	}
	hash := ""
	if stored != nil {
		hash = *stored
	}
	// An account created through single sign-on has no password; setting
	// one is allowed, and there is nothing to verify first.
	if hash != "" {
		userKey, ipKey := "user:"+email, "ip:"+ip
		if locked, err := s.locked(ctx, userKey, ipKey); err != nil {
			return err
		} else if locked {
			return ErrLocked
		}
		ok, _, err := VerifyPassword(hash, current)
		if err != nil {
			return err
		}
		if !ok {
			s.failed(ctx, userKey, ipKey)
			return ErrWrongPassword
		}
		s.clear(ctx, userKey, ipKey)
	}
	return s.SetPassword(ctx, userID, orgID, next)
}

// SetPassword applies the policy, refuses a recently used password and
// stores the new one.
func (s *Service) SetPassword(ctx context.Context, userID, orgID, next string) error {
	policy, err := s.LoadPolicy(ctx, orgID)
	if err != nil {
		return err
	}
	if err := CheckPolicy(next, policy); err != nil {
		return err
	}
	if policy.History > 0 {
		reused, err := s.passwordReused(ctx, userID, next, policy.History)
		if err != nil {
			return err
		}
		if reused {
			return ErrPasswordReused
		}
	}
	hashed, err := HashPassword(next)
	if err != nil {
		return err
	}
	return s.DB.Pre(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT auth_password_set($1,$2,$3)`, userID, hashed, policy.History)
		return err
	})
}

// passwordReused compares against the stored hashes. Each comparison is a
// full argon2id derivation, which is why the history is small.
func (s *Service) passwordReused(ctx context.Context, userID, candidate string, depth int) (bool, error) {
	var hashes []string
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT hash FROM auth_password_history($1,$2)`, userID, depth)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var h string
			if err := rows.Scan(&h); err != nil {
				return err
			}
			hashes = append(hashes, h)
		}
		return rows.Err()
	})
	if err != nil {
		return false, err
	}
	for _, h := range hashes {
		ok, _, err := VerifyPassword(h, candidate)
		if err != nil {
			continue // an unreadable historic hash must not block a change
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// PasswordExpired reports whether the policy's maximum age has passed.
//
// A password that was never changed is as old as the account: the column
// is only written on a change, and reading it alone let every password
// set at registration live for ever.
//
// The answer is checked on every request, and costs two queries: the
// policy and the password's date. A password found to be within its age
// is remembered for a minute, the way a session's idle timer is touched
// at most once a minute, so a busy session pays for the check sixty
// times an hour rather than on every call. Only that answer is cached.
// An expired password is re-read every time, so a change made on
// another replica is seen at once, and the gate never holds someone
// past the moment they have done what it asked. What a replica can be
// late to notice, by at most a minute, is a password crossing its age
// or a policy tightened elsewhere.
func (s *Service) PasswordExpired(ctx context.Context, userID, orgID string) (bool, error) {
	key := userID + "\x00" + orgID
	now := s.now()
	s.freshMu.Lock()
	seen, ok := s.fresh[key]
	s.freshMu.Unlock()
	if ok && now.Sub(seen) < passwordAgeCacheFor {
		return false, nil
	}
	policy, err := s.LoadPolicy(ctx, orgID)
	if err != nil {
		return false, err
	}
	expired := false
	if policy.MaxAgeDays > 0 {
		var set time.Time
		err = s.DB.Bypass(ctx, "password-age", func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT COALESCE(password_changed_at, created_at) FROM users WHERE id = $1`, userID).Scan(&set)
		})
		if err != nil {
			return false, err
		}
		expired = now.Sub(set) > time.Duration(policy.MaxAgeDays)*24*time.Hour
	}
	if !expired {
		s.rememberFresh(key, now)
	}
	return expired, nil
}

// passwordAgeCacheFor is how long a password found within its age is
// taken on trust before it is read again.
const passwordAgeCacheFor = time.Minute

// rememberFresh records a password within its age. The map is bounded by
// the number of signed-in people, and stale entries are dropped when it
// grows past a size no workspace reaches by accident.
func (s *Service) rememberFresh(key string, at time.Time) {
	s.freshMu.Lock()
	defer s.freshMu.Unlock()
	if s.fresh == nil {
		s.fresh = map[string]time.Time{}
	}
	if len(s.fresh) >= 10000 {
		for k, t := range s.fresh {
			if at.Sub(t) >= passwordAgeCacheFor {
				delete(s.fresh, k)
			}
		}
	}
	s.fresh[key] = at
}

// forgetFresh drops the cached answers a change of policy made stale.
// Every workspace's entries go: a policy is changed a few times in a
// workspace's life, and a minute of re-reads is cheaper than a second map.
func (s *Service) forgetFresh() {
	s.freshMu.Lock()
	defer s.freshMu.Unlock()
	clear(s.fresh)
}

// SessionPasswordExpired reports whether a session's password is past the
// workspace's maximum age. Only a password sign-in has a password to age:
// a person who came in through an identity provider is exempt, since the
// provider owns their credential.
func (s *Service) SessionPasswordExpired(ctx context.Context, sess *Session) (bool, error) {
	if sess.AuthMethod != "password" {
		return false, nil
	}
	return s.PasswordExpired(ctx, sess.UserID, sess.OrgID)
}

// RevokeEverything ends a principal's sessions and revokes their keys and
// refresh tokens. Deactivation has to reach every credential, or the
// account keeps working after it was switched off.
func (s *Service) RevokeEverything(ctx context.Context, orgID, userID, reason string) error {
	return s.DB.Pre(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT auth_revoke_principal($1,$2,$3)`, orgID, userID, reason)
		return err
	})
}

// Sessions lists a user's live sessions for the security screen.
func (s *Service) Sessions(ctx context.Context, orgID, userID string) ([]SessionInfo, error) {
	out := []SessionInfo{}
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, created_at, last_seen_at, idle_expires_at, auth_method,
			COALESCE(host(ip),''), COALESCE(user_agent,'') FROM sessions
			WHERE user_id = $1 AND revoked_at IS NULL AND idle_expires_at > now()
			ORDER BY last_seen_at DESC`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s SessionInfo
			if err := rows.Scan(&s.ID, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt, &s.AuthMethod, &s.IP, &s.UserAgent); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

// SessionInfo is a session as the owner sees it.
type SessionInfo struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	AuthMethod string    `json:"authMethod"`
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"userAgent,omitempty"`
}
