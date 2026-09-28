package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/tenant"
)

// MaxNameLength is the most characters a person's display name or an
// organisation's name may have, counted after trimming.
const MaxNameLength = 120

// ErrInvalidName refuses a name that is empty once trimmed, longer than
// MaxNameLength, or holds a control or bidirectional formatting
// character. The message never quotes the name.
var ErrInvalidName = errors.New("a name must be 1 to 120 characters with no control characters")

// CleanName trims a display name and checks it. Bidirectional formatting
// characters are refused with the control characters: in a name other
// people read, they reorder what is shown and can make it pass for
// another.
func CleanName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxNameLength {
		return "", ErrInvalidName
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return "", ErrInvalidName
		}
	}
	return s, nil
}

// RenameUser sets a user's display name and returns the name it had. It
// runs under orgID's tenant, where the row is visible only while the
// user is a member, and changes nothing but the name.
func (s *Service) RenameUser(ctx context.Context, orgID, userID, name string) (before, after string, err error) {
	after, err = CleanName(name)
	if err != nil {
		return "", "", err
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
	clean, err := CleanName(name)
	if err != nil {
		return Org{}, Org{}, err
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
