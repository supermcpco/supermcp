package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// argon2id parameters (OWASP 2024 recommendation, second option).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// PasswordPolicy is the org's password policy.
type PasswordPolicy struct {
	MinLength int `json:"minLength"`
	// RequireClasses is how many of lower case, upper case, digits and
	// symbols a password must use.
	RequireClasses int `json:"requireClasses"`
	// History is how many previous passwords may not be reused.
	History int `json:"history"`
	// MaxAgeDays forces a change after this long; 0 never expires.
	MaxAgeDays int `json:"maxAgeDays"`
}

// DefaultPolicy applies when an org has not set one. Length does most of
// the work; the class requirement keeps out the trivially guessable
// without pushing people towards "Password1!".
var DefaultPolicy = PasswordPolicy{MinLength: 12, RequireClasses: 2, History: 5}

// ErrWeakPassword is returned by CheckPolicy.
var ErrWeakPassword = errors.New("password does not meet the policy")

// CheckPolicy validates a new password against the organisation's policy.
func CheckPolicy(pw string, p PasswordPolicy) error {
	if p.MinLength <= 0 {
		p.MinLength = DefaultPolicy.MinLength
	}
	if p.RequireClasses <= 0 {
		p.RequireClasses = DefaultPolicy.RequireClasses
	}
	if len(pw) < p.MinLength {
		return fmt.Errorf("%w: at least %d characters", ErrWeakPassword, p.MinLength)
	}
	if len(pw) > 256 {
		return fmt.Errorf("%w: at most 256 characters", ErrWeakPassword)
	}
	if n := classes(pw); n < p.RequireClasses {
		return fmt.Errorf("%w: use at least %d of lower case, upper case, digits and symbols", ErrWeakPassword, p.RequireClasses)
	}
	return nil
}

// classes counts how many character classes a password draws on.
func classes(pw string) int {
	var lower, upper, digit, other bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, has := range []bool{lower, upper, digit, other} {
		if has {
			n++
		}
	}
	return n
}

// HashPassword returns a PHC-formatted argon2id hash.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks pw against an argon2id or legacy bcrypt hash.
// upgrade reports that the stored hash should be replaced (bcrypt or
// weaker argon2 parameters).
func VerifyPassword(hash, pw string) (ok bool, upgrade bool, err error) {
	switch {
	case strings.HasPrefix(hash, "$argon2id$"):
		parts := strings.Split(hash, "$")
		if len(parts) != 6 {
			return false, false, errors.New("malformed argon2id hash")
		}
		var m, t uint32
		var p uint8
		if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
			return false, false, err
		}
		salt, err := base64.RawStdEncoding.DecodeString(parts[4])
		if err != nil {
			return false, false, err
		}
		want, err := base64.RawStdEncoding.DecodeString(parts[5])
		if err != nil {
			return false, false, err
		}
		got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want))) //nolint:gosec // want is a 32-byte digest
		ok = subtle.ConstantTimeCompare(got, want) == 1
		upgrade = ok && (m < argonMemory || t < argonTime)
		return ok, upgrade, nil
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw))
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, false, nil
		}
		return err == nil, err == nil, err
	case hash == "":
		return false, false, nil
	}
	return false, false, errors.New("unsupported password hash format")
}

// dummyHash is verified against on unknown users so timing does not reveal
// whether an email exists.
var dummyHash, _ = HashPassword("supermcp-dummy-password-for-timing-only")
