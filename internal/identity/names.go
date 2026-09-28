package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"golang.org/x/text/unicode/norm"

	"github.com/supermcpco/supermcp/internal/tenant"
)

// MaxNameLength is the most characters a person's display name or an
// organisation's name may have, counted after normalising and trimming.
const MaxNameLength = 120

// ErrInvalidName refuses a name that is empty once trimmed, longer than
// MaxNameLength, blank to the eye, or holds a control or invisible
// formatting character. The message never quotes the name.
var ErrInvalidName = errors.New("a name must be 1 to 120 characters, no control or invisible formatting characters")

// ErrNameManaged refuses renaming a person whose identity provider
// provisions them through SCIM, in any organisation: the provider owns
// the name and would put its own back.
var ErrNameManaged = errors.New("your identity provider manages your name; change it there")

// InvalidNameError is ErrInvalidName for one field of a request, so the
// refusal can point at the field that carried the name.
type InvalidNameError struct {
	// Field is the request field, as the client spelled it: name or orgName.
	Field string
}

func (e *InvalidNameError) Error() string { return ErrInvalidName.Error() }

// Unwrap makes errors.Is(err, ErrInvalidName) hold.
func (e *InvalidNameError) Unwrap() error { return ErrInvalidName }

// CleanName normalises a display name to NFC, trims it and checks it. A
// name other people read must not be able to pass for another, or for
// nobody, so besides the control characters it refuses:
//   - format characters (Cf), which include the bidirectional controls
//     and zero-width characters, except the zero-width non-joiner and
//     joiner that some scripts and emoji sequences need;
//   - line and paragraph separators (Zl, Zp), private-use (Co) and
//     unassigned (Cn) code points;
//   - a name with no rune that is neither white space nor default
//     ignorable, such as a lone zero-width space, a Hangul filler or a
//     blank Braille pattern.
func CleanName(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", ErrInvalidName
	}
	s = strings.TrimSpace(norm.NFC.String(s))
	if s == "" || utf8.RuneCountInString(s) > MaxNameLength {
		return "", ErrInvalidName
	}
	visible := false
	for _, r := range s {
		if refusedInName(r) {
			return "", ErrInvalidName
		}
		if !blank(r) {
			visible = true
		}
	}
	if !visible {
		return "", ErrInvalidName
	}
	return s, nil
}

// cleanField is CleanName for an optional request field: empty stays
// empty, and a refusal names the field.
func cleanField(field, s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "", nil
	}
	clean, err := CleanName(s)
	if err != nil {
		return "", &InvalidNameError{Field: field}
	}
	return clean, nil
}

// ProviderName is the name an identity provider asserted, cleaned, or
// empty when CleanName refuses it. A sign-in is not refused over a name
// it did not choose; the account keeps the name it had.
func ProviderName(s string) string {
	clean, err := CleanName(s)
	if err != nil {
		return ""
	}
	return clean
}

const (
	zwnj = '\u200c'
	zwj  = '\u200d'
	// brailleBlank is a Braille pattern with no dots: a symbol by
	// category, and invisible.
	brailleBlank = '\u2800'
)

func refusedInName(r rune) bool {
	switch {
	case r == zwnj, r == zwj:
		return false
	case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Bidi_Control, r),
		unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r), unicode.Is(unicode.Co, r):
		return true
	}
	return unassigned(r)
}

// assigned are the general categories but Cn. unicode.C is not used: it
// covers unassigned code points too.
var assigned = []*unicode.RangeTable{unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z,
	unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs}

func unassigned(r rune) bool {
	return !unicode.In(r, assigned...)
}

// blank reports whether r shows nothing: white space, a default
// ignorable code point, or the blank Braille pattern.
func blank(r rune) bool {
	return unicode.IsSpace(r) || r == brailleBlank ||
		unicode.In(r, unicode.Other_Default_Ignorable_Code_Point, unicode.Cf, unicode.Variation_Selector)
}

// RenameUser sets a user's display name and returns the name it had. It
// runs under orgID's tenant, where the row is visible only while the
// user is a member, and changes nothing but the name.
func (s *Service) RenameUser(ctx context.Context, orgID, userID, name string) (before, after string, err error) {
	after, err = cleanField("name", name)
	if err != nil {
		return "", "", err
	}
	if after == "" {
		return "", "", &InvalidNameError{Field: "name"}
	}
	managed, err := s.nameManaged(ctx, userID)
	if err != nil {
		return "", "", err
	}
	if managed {
		return "", "", ErrNameManaged
	}
	err = s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE users u SET name = $2, updated_at = now()
			FROM (SELECT id, name FROM users WHERE id = $1 FOR UPDATE) old
			WHERE u.id = old.id
			RETURNING old.name`, userID, after).Scan(&before)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotMember
	}
	if err != nil {
		return "", "", fmt.Errorf("rename user: %w", err)
	}
	return before, after, nil
}

// RenameOrg sets an organisation's name and returns it as it was and as
// it is now. The slug stays: links and exports name the organisation by
// it.
func (s *Service) RenameOrg(ctx context.Context, orgID, name string) (before, after Org, err error) {
	clean, err := cleanField("name", name)
	if err != nil {
		return Org{}, Org{}, err
	}
	if clean == "" {
		return Org{}, Org{}, &InvalidNameError{Field: "name"}
	}
	err = s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE organizations o SET name = $2, updated_at = now()
			FROM (SELECT id, name FROM organizations WHERE id = $1 FOR UPDATE) old
			WHERE o.id = old.id
			RETURNING o.id, o.slug, old.name, o.name`, orgID, clean).
			Scan(&after.ID, &after.Slug, &before.Name, &after.Name)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Org{}, Org{}, ErrNotMember
	}
	if err != nil {
		return Org{}, Org{}, fmt.Errorf("rename organisation: %w", err)
	}
	before.ID, before.Slug = after.ID, after.Slug
	return before, after, nil
}

// nameManaged reports whether SCIM provisions the user in any
// organisation. It reads past row-level security: the organisation that
// provisions them need not be the one the session has selected.
func (s *Service) nameManaged(ctx context.Context, userID string) (bool, error) {
	var managed bool
	err := s.DB.Bypass(ctx, "identity:rename checks SCIM provisioning in every workspace the person belongs to",
		func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scim_users WHERE user_id = $1)`, userID).Scan(&managed)
		})
	if err != nil {
		return false, fmt.Errorf("check scim provisioning: %w", err)
	}
	return managed, nil
}
