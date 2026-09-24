package compliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
)

// A subject access request and an erasure both reach every workspace the
// person belongs to and, for the audit stream, rows that belong to no
// workspace at all. Neither can be expressed as a tenant-scoped read, so
// both run through Bypass with a reason that says whose record is being
// opened and why.

// ErrNoSubject is returned when no account matches.
var ErrNoSubject = errors.New("no account with that id or email address")

// Recorder appends an event and waits for it to land. A subject access
// request and an erasure are both privileged acts on one person's record,
// and a record of them that might not have been written is not a record.
// *audit.Writer satisfies it.
type Recorder interface {
	EmitSync(ctx context.Context, e audit.Event) error
}

// Subject is the person a request is about.
type Subject struct {
	UserID            string     `json:"userId"`
	Email             string     `json:"email"`
	Name              string     `json:"name"`
	CreatedAt         time.Time  `json:"createdAt"`
	UpdatedAt         time.Time  `json:"updatedAt"`
	DisabledAt        *time.Time `json:"disabledAt,omitempty"`
	PasswordChangedAt *time.Time `json:"passwordChangedAt,omitempty"`
	// HasPassword says whether the account can sign in with a password.
	// The hash itself never leaves, and a digest of it would be no more
	// use to the subject than this.
	HasPassword bool `json:"hasPassword"`
}

// FindSubject resolves an id or an email address to one account.
func FindSubject(ctx context.Context, d Deps, idOrEmail string) (*Subject, error) {
	var s Subject
	found := false
	err := d.DB.Bypass(ctx, "compliance:dsar resolves a person, who belongs to no single workspace", func(tx pgx.Tx) error {
		var hash *string
		err := tx.QueryRow(ctx, `
SELECT id, email, COALESCE(name, ''), created_at, updated_at, disabled_at, password_changed_at, password_hash
FROM users WHERE id = $1 OR email_lower = lower($1)`, idOrEmail).
			Scan(&s.UserID, &s.Email, &s.Name, &s.CreatedAt, &s.UpdatedAt, &s.DisabledAt, &s.PasswordChangedAt, &hash)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		s.HasPassword = hash != nil && *hash != ""
		found = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %q", ErrNoSubject, idOrEmail)
	}
	return &s, nil
}

// ---------------------------------------------------------------------------
// Erasure

// Pseudonym is the stable stand-in for one person's name and address. It
// is derived from the account id, which stays in the database either way
// as the key every other row points at, so deriving it there adds nothing
// an attacker did not already have, and makes a second run of the command
// change nothing.
func Pseudonym(userID string) string {
	sum := sha256.Sum256([]byte("supermcp-erasure\x00" + userID))
	return "erased-" + hex.EncodeToString(sum[:6])
}

// PseudonymAddress is the address that replaces the real one. The domain
// is reserved by RFC 2606 and can never be delivered to, and the local
// part is unique per account, so the unique index on the address holds
// after an erasure as it did before.
func PseudonymAddress(userID string) string { return Pseudonym(userID) + "@erased.invalid" }

// EraseOptions tunes an erasure.
type EraseOptions struct {
	// Audit records the erasure in the stream it edited. Nil skips it,
	// which a test may want and an operator should not.
	Audit Recorder
}

// TableChange is what an erasure did to one table.
type TableChange struct {
	Table   string   `json:"table"`
	Columns []string `json:"columns"`
	Rows    int64    `json:"rows"`
	Why     string   `json:"why"`
}

// Untouched is something the erasure deliberately left, and why. This is
// the half of the report that matters: a person told their name was
// erased, whose name is still in a diff, was misled.
type Untouched struct {
	Where string `json:"where"`
	// Rows counts what still holds the old value where the count can be
	// taken; -1 where it cannot.
	Rows int64  `json:"rows"`
	Why  string `json:"why"`
}

// Erasure is the result of an erasure.
type Erasure struct {
	ErasedAt   time.Time     `json:"erasedAt"`
	UserID     string        `json:"userId"`
	Pseudonym  string        `json:"pseudonym"`
	NewAddress string        `json:"newAddress"`
	Changed    []TableChange `json:"changed"`
	Untouched  []Untouched   `json:"untouched"`
	// Workspaces are the ones the person belonged to, which is where the
	// erasure was recorded.
	Workspaces []string `json:"workspaces"`
}

// eraseTargets are the display columns an erasure may rewrite. Every one
// of them is outside the audit chain's hash, or is in a table the chain
// does not cover at all. The chain covers a row's id, write time,
// workspace, category, action, outcome, actor kind, actor id, target kind,
// target id, and a digest of the three JSON columns. It does not cover
// actor_display or target_display, which is exactly why those two columns
// exist separately from the ids beside them: a name may lawfully have to
// change, an identity may not.
var eraseTargets = []struct {
	table, why string
	columns    []string
	sql        string
	// args builds the statement's parameters. Each statement takes only
	// the values it uses: a parameter a statement never mentions has no
	// type for Postgres to infer, and the whole erasure fails on it.
	args func(userID, pseudonym, address string) []any
}{
	{
		table: "users", columns: []string{"name", "email"},
		why: "the account itself; the id stays, because every other row points at it",
		sql: `UPDATE users SET name = $2, email = $3, updated_at = now()
		      WHERE id = $1 AND email <> $3`,
		args: func(id, pseudonym, address string) []any { return []any{id, pseudonym, address} },
	},
	{
		table: "user_identities", columns: []string{"email"},
		why:  "the address a single sign-on provider last asserted; the provider's subject stays, because it is the link the next sign-in resolves",
		sql:  `UPDATE user_identities SET email = $2 WHERE user_id = $1 AND email <> $2`,
		args: func(id, _, address string) []any { return []any{id, address} },
	},
	{
		table: "scim_users", columns: []string{"user_name", "raw"},
		why: "the provisioning record, whose raw payload holds whatever the provisioning system sent, names and addresses included",
		sql: `UPDATE scim_users SET user_name = $2, raw = NULL, updated_at = now()
		      WHERE user_id = $1 AND (user_name <> $2 OR raw IS NOT NULL)`,
		args: func(id, _, address string) []any { return []any{id, address} },
	},
	{
		table: "audit_events", columns: []string{"actor_display", "target_display"},
		why: "the name shown beside an event; it is outside the chain hash, and the ids it sits next to are inside it",
		sql: `UPDATE audit_events SET
		          actor_display  = CASE WHEN actor_id  = $1 THEN $2 ELSE actor_display  END,
		          target_display = CASE WHEN target_id = $1 THEN $2 ELSE target_display END
		      WHERE (actor_id = $1 AND actor_display <> $2) OR (target_id = $1 AND target_display <> $2)`,
		args: func(id, pseudonym, _ string) []any { return []any{id, pseudonym} },
	},
	{
		table: "revisions", columns: []string{"actor_display"},
		why:  "the name shown beside a configuration change; the snapshot and diff beside it are not touched",
		sql:  `UPDATE revisions SET actor_display = $2 WHERE actor_id = $1 AND actor_display <> $2`,
		args: func(id, pseudonym, _ string) []any { return []any{id, pseudonym} },
	},
	{
		table: "approval_requests", columns: []string{"requester_display"},
		why:  "the name shown on an approval this person raised",
		sql:  `UPDATE approval_requests SET requester_display = $2 WHERE requested_by = $1 AND requester_display <> $2`,
		args: func(id, pseudonym, _ string) []any { return []any{id, pseudonym} },
	},
}

// Erase pseudonymises the display columns that name one person.
//
// It runs in one transaction, so a person is either erased everywhere
// this command reaches or nowhere: a half-finished erasure would leave
// the address in one table and a pseudonym in another, which is the worst
// of both — the person is still identifiable and the record no longer
// reads consistently.
//
// It runs through Bypass for two reasons. The person's rows are in every
// workspace they belonged to, and the application role is not permitted
// to update audit_events at all: after migration 00006 it may null a
// scrubbed row's content and nothing else. Rewriting a display column is
// a maintenance act by construction, which is the right shape for it.
func Erase(ctx context.Context, d Deps, s *Subject, opts EraseOptions) (*Erasure, error) {
	now := d.now()
	e := &Erasure{
		ErasedAt:   now,
		UserID:     s.UserID,
		Pseudonym:  Pseudonym(s.UserID),
		NewAddress: PseudonymAddress(s.UserID),
		Changed:    []TableChange{},
	}
	before := s.Email

	err := d.DB.Bypass(ctx,
		"compliance:dsar-erase rewrites one person's display columns across every workspace and the audit stream, "+
			"which no tenant policy admits and which the application role may not do to audit_events",
		func(tx pgx.Tx) error {
			e.Changed = e.Changed[:0]
			orgs, err := subjectOrgs(ctx, tx, s.UserID)
			if err != nil {
				return err
			}
			e.Workspaces = orgs
			for _, t := range eraseTargets {
				tag, err := tx.Exec(ctx, t.sql, t.args(s.UserID, e.Pseudonym, e.NewAddress)...)
				if err != nil {
					return fmt.Errorf("pseudonymise %s: %w", t.table, err)
				}
				e.Changed = append(e.Changed, TableChange{
					Table: t.table, Columns: t.columns, Rows: tag.RowsAffected(), Why: t.why,
				})
			}
			e.Untouched, err = whatRemains(ctx, tx, s.UserID, before)
			return err
		})
	if err != nil {
		return nil, err
	}

	if opts.Audit != nil {
		if err := recordErasure(ctx, opts.Audit, e); err != nil {
			// The rows are already rewritten, and saying so is more useful
			// than a failure that hides what was done.
			return e, fmt.Errorf("the erasure was applied but could not be recorded in the audit stream: %w", err)
		}
	}
	return e, nil
}

// subjectOrgs lists the workspaces the person belongs to. Memberships
// survive an erasure: they say that somebody was a member, which the
// workspace needs, and they carry no name.
func subjectOrgs(ctx context.Context, tx pgx.Tx, userID string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT organization_id FROM organization_members WHERE user_id = $1 ORDER BY organization_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// whatRemains counts the places the old address still appears and says
// why each one was left. The counts use a plain substring search rather
// than LIKE: an address may contain an underscore, which LIKE reads as a
// wildcard, and a count that quietly over-reports is worse here than one
// that is slower to take.
func whatRemains(ctx context.Context, tx pgx.Tx, userID, email string) ([]Untouched, error) {
	count := func(sql string, args ...any) (int64, error) {
		var n int64
		err := tx.QueryRow(ctx, sql, args...).Scan(&n)
		return n, err
	}
	inEvents, err := count(`SELECT count(*) FROM audit_events
		WHERE strpos(lower(COALESCE(diff::text, '') || COALESCE(payload::text, '') || COALESCE(meta::text, '')), lower($1)) > 0`, email)
	if err != nil {
		return nil, err
	}
	inRevisions, err := count(`SELECT count(*) FROM revisions
		WHERE strpos(lower(snapshot::text || COALESCE(diff::text, '')), lower($1)) > 0`, email)
	if err != nil {
		return nil, err
	}
	inCalls, err := count(`SELECT count(*) FROM tool_invocations
		WHERE strpos(lower(COALESCE(input::text, '') || COALESCE(output::text, '')), lower($1)) > 0`, email)
	if err != nil {
		return nil, err
	}
	ownCalls, err := count(`SELECT count(*) FROM tool_invocations WHERE principal_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	ownEvents, err := count(`SELECT count(*) FROM audit_events WHERE actor_id = $1 OR target_id = $1 OR on_behalf_of = $1`, userID)
	if err != nil {
		return nil, err
	}
	sessions, err := count(`SELECT count(*) FROM sessions WHERE user_id = $1 AND (ip IS NOT NULL OR user_agent IS NOT NULL)`, userID)
	if err != nil {
		return nil, err
	}

	return []Untouched{
		{Where: "audit_events.actor_id, target_id, on_behalf_of", Rows: ownEvents,
			Why: "these are inside the chain hash. Changing one would make every row from that point on fail verification, " +
				"and a tamper-evident record that has been tampered with is no record at all. The id is a generated identifier, " +
				"not a name: on its own it says nothing about who the person is."},
		{Where: "audit_events.diff, payload, meta", Rows: inEvents,
			Why: "the chain covers a digest of these three columns, so their content cannot be rewritten. The address can be " +
				"removed from them, but only by the mechanism that already exists for it: the retention scrub nulls the content " +
				"and marks the row, and verification then proves the row's place in the sequence while saying it could not check " +
				"what the row held. That scrub takes a workspace and a date, not a person, so running it here would erase " +
				"everybody else's content in the same window."},
		{Where: "revisions.snapshot, revisions.diff", Rows: inRevisions,
			Why: "a revision is the record of what a configuration was, and rewriting it would falsify the history it exists to keep. " +
				"Nothing hashes it, so an operator who decides the address must go can remove it; this command does not decide that."},
		{Where: "tool_invocations.principal_id", Rows: ownCalls,
			Why: "the link between a call and who made it. Removing it would leave calls nobody can account for, which is the " +
				"opposite of what the record is for. It is an identifier, not a name."},
		{Where: "tool_invocations.input, tool_invocations.output", Rows: inCalls,
			Why: "arguments and results, kept according to the workspace's audit payload policy. Nothing removes these rows, ever, " +
				"and this count is of rows whose stored arguments contain the address — which may be somebody else's call that " +
				"mentioned this person."},
		{Where: "sessions.ip, sessions.user_agent", Rows: sessions,
			Why: "an address and a browser string are personal data and are not a name; this command pseudonymises names and " +
				"email addresses. Neither column is hashed anywhere, so both can be cleared by an operator who decides they should be."},
		{Where: "users.password_hash, password_history.hash", Rows: -1,
			Why: "argon2id digests. They are not readable and are not a name, and clearing them would silently change whether " +
				"the account can sign in, which is a separate decision from erasure."},
		{Where: "sessions, api_keys, oauth_refresh_tokens", Rows: -1,
			Why: "an erasure revokes nothing. A session or a key that worked before this command still works; " +
				"deactivating the account is a separate act, and SCIM or `active: false` is what does it."},
	}, nil
}

func recordErasure(ctx context.Context, rec Recorder, e *Erasure) error {
	rows := int64(0)
	for _, c := range e.Changed {
		rows += c.Rows
	}
	meta := map[string]any{
		"pseudonym":   e.Pseudonym,
		"rowsChanged": rows,
		"reason":      "subject erasure request",
	}
	orgs := e.Workspaces
	if len(orgs) == 0 {
		// Somebody who belonged to no workspace still leaves a record, as
		// an instance-level event.
		orgs = []string{""}
	}
	for _, org := range orgs {
		// The event carries the pseudonym, never the address: an erasure
		// that recorded what it erased would be a way of keeping it.
		if err := rec.EmitSync(ctx, audit.Event{
			OrgID: org, Category: audit.CategoryAdmin, Action: "dsar.erase", Outcome: audit.Success,
			ActorKind: "system", ActorDisplay: "supermcp dsar erase",
			TargetKind: "user", TargetID: e.UserID, TargetDisplay: e.Pseudonym,
			Meta: meta,
		}); err != nil {
			return err
		}
	}
	return nil
}

// ChainSafeColumns names the audit columns this package rewrites, for the
// documentation and for a test that asserts the list has not grown into
// something the chain covers.
func ChainSafeColumns() []string { return []string{"actor_display", "target_display"} }

// Summary names the subject in one line. The confirmation prompt and the
// report both use it, so what an operator is asked to confirm reads the
// same as what they are afterwards told was done.
func (s *Subject) Summary() string {
	return fmt.Sprintf("%s (%s), account %s", s.Email, orNone(s.Name), s.UserID)
}
