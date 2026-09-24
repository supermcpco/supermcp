package compliance

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/secrets"
)

// CryptoOptions tunes the cryptography report.
type CryptoOptions struct {
	// Keys is the master key set this process holds. With it, every data
	// key is opened with the master key its own row names and the report
	// says whether it opened. Without it the keys are still listed and the
	// report says it did not check, which is a different and weaker claim.
	Keys *secrets.KEKSet
}

// Crypto is what this instance encrypts, under which key, and what it
// does not encrypt at all.
type Crypto struct {
	GeneratedAt time.Time        `json:"generatedAt"`
	MasterKeys  MasterKeys       `json:"masterKeys"`
	DataKeys    []DataKeyState   `json:"dataKeys"`
	SigningKeys []SigningKey     `json:"signingKeys"`
	Sealed      []SealedColumn   `json:"sealedColumns"`
	Clear       []ClearStatement `json:"notEncrypted"`
	Limits      []string         `json:"limits"`
}

// MasterKeys is the top of the hierarchy: the key that wraps the data
// keys, and any key kept only to open what an earlier one wrapped.
type MasterKeys struct {
	Active      string   `json:"active,omitempty"`
	DecryptOnly []string `json:"decryptOnly,omitempty"`
	// Checked is false when no master key was configured for this run.
	Checked bool   `json:"checked"`
	Note    string `json:"note"`
}

// DataKeyState is one row of data_keys and whether it opens.
type DataKeyState struct {
	ID        string    `json:"id"`
	Scope     string    `json:"scope"`
	Status    string    `json:"status"`
	KEKRef    string    `json:"kekRef"`
	CreatedAt time.Time `json:"createdAt"`
	AgeDays   int       `json:"ageDays"`
	// Opens is nil when the run held no master key to try.
	Opens *bool  `json:"opens"`
	Error string `json:"error,omitempty"`

	// wrapped is the key as the database holds it, carried out of the
	// transaction only as far as the unwrap that proves it opens, and
	// zeroed straight afterwards. It is unexported so no report can
	// serialise it by accident.
	wrapped []byte
}

// SigningKey is one token-signing key and where it is in its rotation.
type SigningKey struct {
	KID         string     `json:"kid"`
	Alg         string     `json:"alg"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"createdAt"`
	ActivatedAt *time.Time `json:"activatedAt,omitempty"`
	RetireAt    *time.Time `json:"retireAt,omitempty"`
	AgeDays     int        `json:"ageDays"`
}

// SealedColumn is one encrypted column, found in the schema rather than
// listed here. A list in this file would go stale the first time a feature
// sealed a new column, and it would go stale silently: the report would
// keep saying five columns are encrypted while six were.
type SealedColumn struct {
	Table  string `json:"table"`
	Column string `json:"column"`
	// Scope says which data key seals it: one per workspace, or the
	// instance key.
	Scope string `json:"scope"`
	// Holds is what the column protects, for a reader who does not know
	// the schema. Empty means this report has no description for a column
	// the schema has, which is itself worth printing.
	Holds string `json:"holds,omitempty"`
	Rows  int64  `json:"rows"`
}

// ClearStatement is one thing this instance does not encrypt, said plainly.
type ClearStatement struct {
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
	// Rows counts what is affected where a count is meaningful. -1 means
	// the statement is not about rows.
	Rows int64 `json:"rows,omitempty"`
}

// sealedColumns describes the columns this report knows about. A column
// found in the schema and missing from here is still reported, without a
// description and with a note saying so.
var sealedColumns = map[string]struct{ scope, holds string }{
	"connector_credentials.value_enc":  {"workspace", "the credentials a connector presents to its upstream"},
	"connector_tokens.token_enc":       {"workspace", "OAuth access and refresh tokens obtained at runtime"},
	"identity_providers.client_secret": {"workspace", "the client secret of a single sign-on provider"},
	"audit_exporters.config_enc":       {"workspace", "where a copy of the audit stream is shipped, and the secret it is signed with"},
	"approval_requests.args_enc":       {"workspace", "the arguments sealed when an approval was raised, so the call that runs is the one approved"},
	"signing_keys.private_enc":         {"instance", "the private half of the keys that sign MCP access tokens and audit checkpoints"},
}

// CryptoReport reads the key hierarchy and the schema.
//
// All of it runs through Bypass. Keys and the shape of the schema belong
// to the instance rather than to any tenant: the data_keys policy admits
// one workspace's scope at a time, so a tenant-scoped read would report
// on one workspace's key and call it the answer.
func CryptoReport(ctx context.Context, d Deps, opts CryptoOptions) (*Crypto, error) {
	now := d.now()
	c := &Crypto{
		GeneratedAt: now,
		DataKeys:    []DataKeyState{},
		SigningKeys: []SigningKey{},
		Sealed:      []SealedColumn{},
		Limits: []string{
			"Opening a data key proves this process can decrypt it. It does not prove any particular row opens; " +
				"a ciphertext is also bound to its table, column, row and workspace, and a row moved between any of those fails to open.",
			"Nothing here inspects a backup. A key that opens now opens a backup only if the backup was taken while the same master key was configured.",
			"There is no data key rotation. The code to re-seal a workspace's rows under a new data key exists and no command calls it, " +
				"so every key below was minted on first use and has never been replaced.",
		},
	}
	c.MasterKeys = masterKeys(opts.Keys)

	if err := d.DB.Bypass(ctx, "compliance:crypto-report reads the instance's keys and schema, which belong to no tenant", func(tx pgx.Tx) error {
		var err error
		if c.DataKeys, err = readDataKeys(ctx, tx, now); err != nil {
			return fmt.Errorf("read data keys: %w", err)
		}
		if c.SigningKeys, err = readSigningKeys(ctx, tx, now); err != nil {
			return fmt.Errorf("read signing keys: %w", err)
		}
		if c.Sealed, err = readSealedColumns(ctx, tx); err != nil {
			return fmt.Errorf("read sealed columns: %w", err)
		}
		if c.Clear, err = readClear(ctx, tx); err != nil {
			return fmt.Errorf("count what is not encrypted: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if opts.Keys != nil {
		openDataKeys(ctx, opts.Keys, c.DataKeys)
	}
	return c, nil
}

func masterKeys(set *secrets.KEKSet) MasterKeys {
	if set == nil || set.Active == nil {
		return MasterKeys{Checked: false, Note: "no master key was configured for this run, so no data key was opened. " +
			"Set the same ENCRYPTION_KEK or SUPERMCP_KEK_PROVIDER the gateway runs with to check that they open."}
	}
	m := MasterKeys{Active: set.Active.Ref(), Checked: true,
		Note: "each data key was opened with the master key its own row names, never with every key in turn"}
	for _, k := range set.Previous {
		m.DecryptOnly = append(m.DecryptOnly, k.Ref())
	}
	return m
}

func readDataKeys(ctx context.Context, tx pgx.Tx, now time.Time) ([]DataKeyState, error) {
	rows, err := tx.Query(ctx, `SELECT id, scope, kek_ref, status, created_at, wrapped FROM data_keys ORDER BY scope, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DataKeyState{}
	for rows.Next() {
		var k DataKeyState
		var id []byte
		if err := rows.Scan(&id, &k.Scope, &k.KEKRef, &k.Status, &k.CreatedAt, &k.wrapped); err != nil {
			return nil, err
		}
		// The id is not a secret: it travels in the clear in the header of
		// every ciphertext it sealed, so printing it lets an operator match
		// a row to a key.
		k.ID = hex.EncodeToString(id)
		k.AgeDays = int(now.Sub(k.CreatedAt).Hours() / 24)
		out = append(out, k)
	}
	return out, rows.Err()
}

// openDataKeys proves each key opens under the master key its own row
// names, never under every key in turn: a blob substituted in
// data_keys.wrapped gets exactly one decryption attempt, which is the
// property the sealer relies on and the property this report checks.
func openDataKeys(ctx context.Context, set *secrets.KEKSet, keys []DataKeyState) {
	for i := range keys {
		k := &keys[i]
		no, yes := false, true
		kek, ok := set.Find(k.KEKRef)
		if !ok {
			k.Opens, k.Error = &no, "this process holds no master key with that reference"
			continue
		}
		k.Opens, k.Error = &yes, ""
		if err := probeKey(ctx, kek, k.wrapped); err != nil {
			k.Opens, k.Error = &no, err.Error()
		}
		k.wrapped = nil
	}
}

// probeKey unwraps a key and throws the material away again.
func probeKey(ctx context.Context, kek secrets.KEK, wrapped []byte) error {
	dek, err := kek.Unwrap(ctx, wrapped)
	if err != nil {
		return err
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()
	if len(dek) != 32 {
		return fmt.Errorf("unwrapped to %d bytes, want 32", len(dek))
	}
	return nil
}

func readSigningKeys(ctx context.Context, tx pgx.Tx, now time.Time) ([]SigningKey, error) {
	rows, err := tx.Query(ctx, `SELECT kid, alg, status, created_at, activated_at, retire_at
		FROM signing_keys ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SigningKey{}
	for rows.Next() {
		var k SigningKey
		if err := rows.Scan(&k.KID, &k.Alg, &k.Status, &k.CreatedAt, &k.ActivatedAt, &k.RetireAt); err != nil {
			return nil, err
		}
		since := k.CreatedAt
		if k.ActivatedAt != nil {
			since = *k.ActivatedAt
		}
		k.AgeDays = int(now.Sub(since).Hours() / 24)
		out = append(out, k)
	}
	return out, rows.Err()
}

// readSealedColumns finds the encrypted columns in the schema itself. The
// convention is a bytea column whose name ends in _enc, which is what
// every sealed column in this system is called.
func readSealedColumns(ctx context.Context, tx pgx.Tx) ([]SealedColumn, error) {
	rows, err := tx.Query(ctx, `
SELECT table_name, column_name FROM information_schema.columns
WHERE table_schema = 'public' AND data_type = 'bytea' AND column_name LIKE '%\_enc'
ORDER BY table_name, column_name`)
	if err != nil {
		return nil, err
	}
	found := []SealedColumn{}
	for rows.Next() {
		var s SealedColumn
		if err := rows.Scan(&s.Table, &s.Column); err != nil {
			rows.Close()
			return nil, err
		}
		found = append(found, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range found {
		s := &found[i]
		// identity_providers.client_secret_enc is described under a shorter
		// key so the map reads as prose; match on the prefix.
		for key, desc := range sealedColumns {
			if key == s.Table+"."+s.Column || key+"_enc" == s.Table+"."+s.Column {
				s.Scope, s.Holds = desc.scope, desc.holds
				break
			}
		}
		if s.Scope == "" {
			s.Scope = "unknown"
		}
		var n int64
		// The table name comes from information_schema, not from a caller,
		// so there is nothing here an operator could inject.
		if err := tx.QueryRow(ctx, fmt.Sprintf(
			`SELECT count(*) FROM %s WHERE %s IS NOT NULL`, pq(s.Table), pq(s.Column))).Scan(&n); err != nil { //nolint:gosec // identifiers come from information_schema
			return nil, err
		}
		s.Rows = n
	}
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].Table != found[j].Table {
			return found[i].Table < found[j].Table
		}
		return found[i].Column < found[j].Column
	})
	return found, nil
}

// pq quotes an identifier. The identifiers here come from
// information_schema and cannot carry a quote, but quoting them is what
// makes that true by construction rather than by inspection.
func pq(id string) string {
	out := make([]byte, 0, len(id)+2)
	out = append(out, '"')
	for i := 0; i < len(id); i++ {
		if id[i] == '"' {
			out = append(out, '"')
		}
		out = append(out, id[i])
	}
	return string(append(out, '"'))
}

// readClear states what is not encrypted, and counts it where a count
// makes the statement concrete. A control mapping that says "the database
// is not encrypted" is an abstraction; "412 tool calls hold their
// arguments in the clear" is the same fact an assessor can act on.
func readClear(ctx context.Context, tx pgx.Tx) ([]ClearStatement, error) {
	count := func(sql string) (int64, error) {
		var n int64
		err := tx.QueryRow(ctx, sql).Scan(&n)
		return n, err
	}
	invocations, err := count(`SELECT count(*) FROM tool_invocations WHERE input IS NOT NULL OR output IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	events, err := count(`SELECT count(*) FROM audit_events WHERE diff IS NOT NULL OR payload IS NOT NULL OR meta IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	connectors, err := count(`SELECT count(*) FROM connectors`)
	if err != nil {
		return nil, err
	}
	return []ClearStatement{
		{Subject: "the database as a whole",
			Detail: "This software does not encrypt the database. Disk or volume encryption for Postgres is the operator's, " +
				"and everything below is readable by anyone who can read the files or a backup of them."},
		{Subject: "tool-call arguments and results", Rows: invocations,
			Detail: "tool_invocations.input and .output are stored in the clear. What they hold is decided by the workspace's " +
				"audit payload policy, which by default keeps the shape of the arguments and none of their values; a workspace " +
				"that set the policy to full keeps every argument of every call, in the clear, indefinitely, because nothing removes these rows."},
		{Subject: "audit diffs, payloads and metadata", Rows: events,
			Detail: "audit_events.diff, .payload and .meta are stored in the clear. Fields whose names look like secrets are " +
				"replaced with a digest before they are written; a secret in a field with an ordinary name is not."},
		{Subject: "connector configuration", Rows: connectors,
			Detail: "connectors.transport and .auth hold hosts, paths, headers and the names of credentials in the clear. " +
				"Only the credential values are sealed."},
		{Subject: "passwords and bearer credentials",
			Detail: "Passwords are argon2id; API keys, refresh tokens, OAuth client secrets and service account secrets are SHA-256 digests. " +
				"These are not encrypted and are not meant to be: they are not recoverable, which is stronger."},
		{Subject: "traffic between the client and this gateway",
			Detail: "This binary serves plain HTTP. TLS is terminated by the ingress or reverse proxy in front of it, which is the operator's."},
		{Subject: "traffic between this gateway and an upstream",
			Detail: "Whatever the upstream offers. Adapters use https base URLs and nothing forces it; a connector may opt out of " +
				"certificate verification, and only in combination with an explicit outbound proxy."},
	}, nil
}
