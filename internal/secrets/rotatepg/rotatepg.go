// Package rotatepg applies data key rotation to the gateway's own tables.
//
// The secrets package knows how to re-seal a row but deliberately not
// which rows exist: the sealed columns belong to connectors, identity,
// audit and governance, and a list living next to the cipher would go
// stale the first time one of them grew a column. This package is where
// that list is allowed to live, because it is also where the list is
// checked against the schema — see Check. A catalogue that cannot be
// silently wrong is worth having; one that can is the thing the comment
// in rotate.go warns about.
//
// Everything here runs on the maintenance pool, outside row-level
// security. A rotation spans a whole organisation's rows including ones
// no request would ever be allowed to read, and the instance scope
// belongs to no tenant at all.
package rotatepg

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// keyIDLen is the length of a data key id, as the ciphertext header
// carries it. Declared again here rather than exported from secrets
// because it is a property of the stored format, which this package reads
// in SQL: substring(col from 2 for 16) is the same sixteen bytes.
const keyIDLen = 16

// sealedSuffix is the naming convention every sealed column follows. Check
// uses it to find columns the catalogue below has not been told about, so
// a new sealed column that follows the convention cannot be missed and one
// that does not is a review comment waiting to happen.
const sealedSuffix = "_enc"

// Target is one sealed column, with what rotation needs to know about
// where it lives on top of what re-sealing needs to know.
type Target struct {
	secrets.ReSealTarget
	// OrgColumn carries the owning organisation. It is empty for the
	// columns sealed under the instance key, which belong to no tenant.
	OrgColumn string
}

// Targets is every sealed column in the schema.
//
// IDColumn is the expression that yields the row's binding, and it has to
// match, character for character, what the owning package puts in
// AAD.RowID — that is the whole contract. A connector credential is bound
// by "<connector id>/<name>" because its primary key is composite and its
// owner builds the binding that way, so the expression concatenates the
// two halves rather than naming one of them.
//
// Table, column and expression are compile-time constants from this list
// alone and never come from input, which is what makes interpolating them
// into SQL below safe.
//
// tool_blobs.data is sealed too, and deliberately not here: a blob lives
// fifteen minutes and may be in Redis rather than Postgres, so no row
// walk could re-seal them all and no census could count them. The cost is
// that a data key retired within fifteen minutes of its rotation can
// still be named by a blob; the operations guide says to wait.
var Targets = []Target{
	{secrets.ReSealTarget{Table: "connector_credentials", Column: "value_enc",
		IDColumn: "(connector_id || '/' || name)"}, "organization_id"},
	{secrets.ReSealTarget{Table: "connector_tokens", Column: "token_enc",
		IDColumn: "connector_id"}, "organization_id"},
	{secrets.ReSealTarget{Table: "identity_providers", Column: "client_secret_enc",
		IDColumn: "id"}, "organization_id"},
	{secrets.ReSealTarget{Table: "audit_exporters", Column: "config_enc",
		IDColumn: "id"}, "organization_id"},
	{secrets.ReSealTarget{Table: "approval_requests", Column: "args_enc",
		IDColumn: "id"}, "organization_id"},
	{secrets.ReSealTarget{Table: "saml_providers", Column: "signing_key_enc",
		IDColumn: "id"}, "organization_id"},
	// The signing keys' private halves are sealed under the instance key:
	// they sign tokens for every tenant and belong to none.
	{secrets.ReSealTarget{Table: "signing_keys", Column: "private_enc",
		IDColumn: "kid"}, ""},
}

// ScopeTargets filters a checked catalogue to the columns sealed under one
// scope. An organisation's rotation must not touch the instance columns
// and the instance rotation must not touch a tenant's, because a value
// re-sealed under the wrong scope's key is bound to a key its owner will
// never look up.
//
// The catalogue comes from Check rather than from the package variable, so
// a rotation cannot be started against a list nothing has compared to the
// schema.
func ScopeTargets(deployed []Target, scope string) []secrets.ReSealTarget {
	instance := scope == secrets.ScopeInstance
	out := make([]secrets.ReSealTarget, 0, len(deployed))
	for _, t := range deployed {
		if (t.OrgColumn == "") == instance {
			out = append(out, t.ReSealTarget)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Row store

// Store reads and writes the sealed columns of one scope. It satisfies
// both halves of what rotation asks for: the row walk, and the census that
// says whether a superseded key can be retired.
type Store struct {
	db    *tenant.DB
	scope string
	orgID string // empty for the instance scope
	by    map[string]Target
}

var (
	_ secrets.RowStore    = (*Store)(nil)
	_ secrets.CensusStore = (*Store)(nil)
)

// NewStore builds a row store for one scope, which is either
// secrets.ScopeInstance or secrets.ScopeOrg(id).
func NewStore(db *tenant.DB, scope string) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("rotatepg: no database")
	}
	org, err := OrgOf(scope)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, scope: scope, orgID: org, by: map[string]Target{}}
	for _, t := range Targets {
		s.by[t.String()] = t
	}
	return s, nil
}

// OrgOf returns the organisation a scope names, or the empty string for
// the instance scope. Anything else is refused rather than guessed at: a
// scope this package does not recognise would produce rows bound to an
// organisation id that is not one.
func OrgOf(scope string) (string, error) {
	if scope == secrets.ScopeInstance {
		return "", nil
	}
	if org, ok := strings.CutPrefix(scope, "org:"); ok && org != "" {
		return org, nil
	}
	return "", fmt.Errorf("rotatepg: %q is not a data key scope", scope)
}

func (s *Store) target(t secrets.ReSealTarget) (Target, error) {
	tg, ok := s.by[t.String()]
	if !ok {
		return Target{}, fmt.Errorf("rotatepg: %s is not a known sealed column", t)
	}
	return tg, nil
}

// filter narrows a statement to this scope's rows. An instance target has
// no organisation column and needs none; an org target must be filtered
// or one tenant's rotation would re-seal another's rows under a key that
// tenant does not hold.
func (s *Store) filter(tg Target, args []any) (string, []any) {
	if tg.OrgColumn == "" {
		return "", args
	}
	args = append(args, s.orgID)
	return fmt.Sprintf(" AND %s = $%d", tg.OrgColumn, len(args)), args
}

// SealedRows returns the next batch of rows that are not already on the
// scope's active data key.
//
// The narrowing is what makes an interrupted rotation cheap to finish
// rather than merely correct to finish: a resumed run reads the rows still
// to move, not the whole table again. It is expressed against data_keys
// rather than against a key id passed in, so the predicate is always "not
// where this row should end up" and cannot drift from the key the
// rotation is actually sealing under.
//
// Rows whose column is null come back too. They are not work, but they are
// worth counting: an operator reading that three identity providers have
// no secret has learnt something, and a row store that hid them would make
// the totals disagree with the table.
func (s *Store) SealedRows(ctx context.Context, t secrets.ReSealTarget, after string, limit int) ([]secrets.SealedRow, error) {
	tg, err := s.target(t)
	if err != nil {
		return nil, err
	}
	args := []any{after, limit, s.scope}
	where, args := s.filter(tg, args)
	q := fmt.Sprintf(`SELECT %[1]s, %[2]s FROM %[3]s
		WHERE %[1]s > $1%[4]s
		  AND substring(%[2]s from 2 for %[5]d) IS DISTINCT FROM
		      (SELECT id FROM data_keys WHERE scope = $3 AND status = 'active')
		ORDER BY %[1]s LIMIT $2`, tg.IDColumn, tg.Column, tg.Table, where, keyIDLen)

	var out []secrets.SealedRow
	err = s.db.Bypass(ctx, "data-key:rows:"+t.String(), func(tx pgx.Tx) error {
		out = nil
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var cursor string
			var value []byte
			if err := rows.Scan(&cursor, &value); err != nil {
				return err
			}
			out = append(out, secrets.SealedRow{
				Cursor: cursor,
				AAD:    secrets.AAD{Table: tg.Table, Column: tg.Column, RowID: cursor, OrgID: s.orgID},
				Value:  value,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", t, err)
	}
	return out, nil
}

// WriteSealed replaces one batch of values in a single transaction and
// reports how many rows it actually changed.
//
// A statement that matches more than one row aborts the whole rotation,
// loudly and by name. It means two rows share a cursor, and since the
// cursor is also the binding, one of those rows is about to be given a
// ciphertext bound to the other's name — unopenable, with its only
// plaintext already overwritten. That is precisely the outcome a rotation
// must never produce, so it is refused before the transaction commits
// rather than counted afterwards.
func (s *Store) WriteSealed(ctx context.Context, t secrets.ReSealTarget, rows []secrets.SealedRow) (int, error) {
	tg, err := s.target(t)
	if err != nil {
		return 0, err
	}
	written := 0
	err = s.db.Bypass(ctx, "data-key:reseal:"+t.String(), func(tx pgx.Tx) error {
		written = 0
		b := &pgx.Batch{}
		for _, r := range rows {
			args := []any{r.Value, r.Cursor}
			where, args := s.filter(tg, args)
			b.Queue(fmt.Sprintf(`UPDATE %s SET %s = $1 WHERE %s = $2%s`,
				tg.Table, tg.Column, tg.IDColumn, where), args...)
		}
		res := tx.SendBatch(ctx, b)
		// Closed twice on the happy path, which pgx allows. The deferred
		// one is for the refusals below: a batch abandoned half way has to
		// be drained before the transaction can be rolled back.
		defer func() { _ = res.Close() }()
		for _, r := range rows {
			tag, err := res.Exec()
			if err != nil {
				return fmt.Errorf("row %q: %w", r.Cursor, err)
			}
			switch n := tag.RowsAffected(); {
			case n > 1:
				return fmt.Errorf("%s row %q matched %d rows: its cursor is also its binding, so one of them would be sealed under a name nothing will look it up by", t, r.Cursor, n)
			case n == 1:
				written++
			}
		}
		return res.Close()
	})
	if err != nil {
		return 0, err
	}
	return written, nil
}

// KeyCensus counts the target's rows by the data key each one names,
// reading the key id straight out of the ciphertext header. Nothing is
// opened and no key material is touched, which is what lets the count be
// taken for every table before a rotation starts.
func (s *Store) KeyCensus(ctx context.Context, t secrets.ReSealTarget) (map[[keyIDLen]byte]int, error) {
	tg, err := s.target(t)
	if err != nil {
		return nil, err
	}
	var args []any
	where, args := s.filter(tg, args)
	q := fmt.Sprintf(`SELECT substring(%[1]s from 2 for %[4]d), count(*) FROM %[2]s
		WHERE %[1]s IS NOT NULL%[3]s GROUP BY 1`, tg.Column, tg.Table, where, keyIDLen)

	out := map[[keyIDLen]byte]int{}
	err = s.db.Bypass(ctx, "data-key:census:"+t.String(), func(tx pgx.Tx) error {
		clear(out)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var n int
			if err := rows.Scan(&raw, &n); err != nil {
				return err
			}
			// A header shorter than a key id is a value this package did
			// not write. Counting it under a truncated id would make it
			// look like a key that could be retired.
			if len(raw) != keyIDLen {
				return fmt.Errorf("%s holds %d rows whose ciphertext has no key id", t, n)
			}
			out[[keyIDLen]byte(raw)] += n
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("census of %s: %w", t, err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Pre-flight

// Check proves the catalogue still describes the schema and returns the
// targets that are actually deployed. It is the reason this package is
// allowed to hold a list of tables at all.
//
// It asks the database which columns are sealed rather than trusting the
// list, so a feature that adds one and forgets this file turns into a
// refusal with the column named instead of a rotation that reports success
// having left it behind. It also refuses an organisation-scoped row with
// no organisation, because such a row is reachable by no scope: no
// per-organisation rotation would move it and no census would count it, so
// the key it sits on would look retirable while it still holds the only
// thing that opens it.
//
// A target whose column is not in the schema is dropped rather than
// refused. It means the migration that adds it has not run here yet —
// installations sit at different migrations, and a rotation that refused
// to run until every one of them had caught up would be unusable during
// exactly the rollouts it is most needed for. Dropping it is safe because
// the check in the other direction is strict: a column that does exist and
// is misspelt in the catalogue is a column nothing names, which fails
// hard. The two halves cannot both be fooled by the same mistake.
func Check(ctx context.Context, db *tenant.DB) ([]Target, error) {
	known := make(map[string]bool, len(Targets))
	for _, t := range Targets {
		known[t.Table+"."+t.Column] = true
	}
	var problems []string
	deployedNames := map[string]bool{}
	err := db.Bypass(ctx, "data-key:coverage", func(tx pgx.Tx) error {
		clear(deployedNames)
		rows, err := tx.Query(ctx, `
			SELECT c.table_name, c.column_name
			  FROM information_schema.columns c
			  JOIN information_schema.tables t
			    ON t.table_schema = c.table_schema AND t.table_name = c.table_name
			 WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE'
			   AND c.data_type = 'bytea' AND c.column_name LIKE $1
			 ORDER BY 1, 2`, "%"+sealedSuffix)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var table, column string
			if err := rows.Scan(&table, &column); err != nil {
				return err
			}
			name := table + "." + column
			if !known[name] {
				problems = append(problems, fmt.Sprintf(
					"%s is sealed but no rotation target names it; add it to rotatepg.Targets with the binding its owner builds",
					name))
				continue
			}
			deployedNames[name] = true
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("check sealed columns: %w", err)
	}

	deployed := make([]Target, 0, len(Targets))
	for _, t := range Targets {
		if deployedNames[t.Table+"."+t.Column] {
			deployed = append(deployed, t)
		}
	}
	if len(problems) == 0 {
		err = db.Bypass(ctx, "data-key:orphans", func(tx pgx.Tx) error {
			for _, t := range deployed {
				if t.OrgColumn == "" {
					continue
				}
				var n int
				q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s IS NULL AND %s IS NOT NULL`,
					t.Table, t.OrgColumn, t.Column)
				if err := tx.QueryRow(ctx, q).Scan(&n); err != nil {
					return err
				}
				if n > 0 {
					problems = append(problems, fmt.Sprintf(
						"%s has %d sealed rows with no organisation, which no scope's rotation can reach", t, n))
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("check for rows no scope owns: %w", err)
		}
	}
	if len(problems) > 0 {
		slices.Sort(problems)
		return nil, fmt.Errorf("the rotation would not cover every sealed value:\n  %s", strings.Join(problems, "\n  "))
	}
	return deployed, nil
}

// Scopes lists every scope with an active data key, instance first and
// then organisations in a stable order.
//
// A scope with no active key has never sealed anything, so there is
// nothing to rotate and nothing to report; the first value it seals will
// mint a key of its own.
func Scopes(ctx context.Context, db *tenant.DB) ([]string, error) {
	var out []string
	err := db.Bypass(ctx, "data-key:scopes", func(tx pgx.Tx) error {
		out = nil
		rows, err := tx.Query(ctx,
			`SELECT scope FROM data_keys WHERE status = 'active' ORDER BY scope <> $1, scope`,
			secrets.ScopeInstance)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list data key scopes: %w", err)
	}
	return out, nil
}
