package identity

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrReauthViaProvider refuses a password re-authentication for a session
// that was signed in through single sign-on. Accepting a password there
// would let a stolen session skip whatever the provider enforces, such as
// its second factor, by way of a password the provider never checks.
var ErrReauthViaProvider = errors.New("this session was signed in through single sign-on; sign in again with that provider")

// Reauthenticate checks the password of the person holding a password
// session and, when it matches, records that they proved who they are
// now. The session keeps its id and its cookie; only its authentication
// time moves.
//
// A wrong password counts against the same lockout as the sign-in form,
// keyed by the account's address and the client address, so a stolen
// session is no better a place to guess the password from than the sign-in
// page.
func (s *Service) Reauthenticate(ctx context.Context, sess *Session, password, ip string) (time.Time, error) {
	if sess.AuthMethod != "password" {
		return time.Time{}, ErrReauthViaProvider
	}
	var email string
	var hash *string
	var disabled *time.Time
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT email, password_hash, disabled_at FROM auth_user_by_id($1)`, sess.UserID).
			Scan(&email, &hash, &disabled)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrSessionInvalid
	}
	if err != nil {
		return time.Time{}, err
	}
	userKey, ipKey := "user:"+email, "ip:"+ip
	if locked, err := s.locked(ctx, userKey, ipKey); err != nil {
		return time.Time{}, err
	} else if locked {
		return time.Time{}, ErrLocked
	}
	stored := ""
	if hash != nil {
		stored = *hash
	}
	ok, _, err := VerifyPassword(stored, password)
	if err != nil {
		return time.Time{}, err
	}
	if !ok {
		s.failed(ctx, userKey, ipKey)
		return time.Time{}, ErrWrongPassword
	}
	if disabled != nil {
		return time.Time{}, ErrDisabled
	}
	s.clear(ctx, userKey, ipKey)
	var at *time.Time
	err = s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT auth_session_reauth($1,$2)`, sess.ID, sess.UserID).Scan(&at)
	})
	if err != nil {
		return time.Time{}, err
	}
	if at == nil {
		// The session was revoked while the password was being checked.
		return time.Time{}, ErrSessionInvalid
	}
	return *at, nil
}
