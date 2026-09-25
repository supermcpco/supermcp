// Rotation comes in two shapes and an operator reaches for a different
// one depending on what went wrong.
//
// RotateKEK changes the master key. Reach for it when the master key
// itself is suspect or is moving: the local key in an environment
// variable is being replaced by AWS KMS, the KMS key is being retired,
// compliance asks for a yearly master key change. It re-wraps every data
// key under the new master key and touches no ciphertext at all, because
// the data keys are the only thing the master key protects. A million
// rows of sealed values are unaffected and the job takes as many KMS
// calls as there are tenants.
//
// RotateDataKey changes a data key. Reach for it when the sealed values
// themselves are suspect — a data key may have been exposed in a heap
// dump or a backup, or a tenant's contract requires periodic re-keying.
// It mints a new data key for one scope and re-seals, in bounded batches,
// the rows sealed under the old one. This one is expensive: it rewrites
// every affected row.
//
// Neither is a substitute for the other. Re-wrapping a data key does not
// change the bytes in any row; re-sealing rows does not change which
// master key protects the key that sealed them.

package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// statusDecryptOnly is the data_keys status a key moves to when it stops
// sealing new values but must still open old ones. statusRetired is where
// it lands once nothing references it; the key is still readable, because
// a restored backup predates the rotation that superseded it.
const (
	statusDecryptOnly = "decrypt_only"
	statusRetired     = "retired"
)

// defaultReSealBatch is how many rows one transaction re-seals. Large
// enough that the round trips are not the cost, small enough that a
// rotation can be interrupted at any point without a long rollback.
const defaultReSealBatch = 500

// ---------------------------------------------------------------------------
// KEK rotation

// KEKRotationStore is the store surface re-wrapping needs. It is declared
// here, next to its only caller, so the everyday KeyStore stays as narrow
// as the request path requires: serving traffic never lists or rewrites
// keys. An implementation must read and write across every tenant, which
// means running outside row-level security.
type KEKRotationStore interface {
	// ListDataKeys returns every data key, of every scope and status,
	// including retired ones: a retired key still has to be readable to
	// open an old backup.
	ListDataKeys(ctx context.Context) ([]*DataKey, error)
	// ReWrapDataKey replaces one key's wrapped material and its KEK
	// reference together, in a single statement. Together is what makes
	// the job resumable: a row is either entirely on the old master key or
	// entirely on the new one, never a blob from one described by the
	// reference of the other.
	ReWrapDataKey(ctx context.Context, id [keyIDLen]byte, kekRef string, wrapped []byte) error
}

// KEKRotation configures RotateKEK.
type KEKRotation struct {
	Store KEKRotationStore
	// To is the master key every data key should end up under.
	To KEK
	// From lists every master key that might currently wrap a data key.
	// More than one is normal: an earlier rotation that stopped half way
	// leaves keys under two masters, and finishing it needs both.
	From []KEK
	Log  *slog.Logger
}

// KEKReport says how far RotateKEK got.
type KEKReport struct {
	// Examined counts keys looked at, Skipped those already under To from
	// an earlier run, ReWrapped those this run moved.
	Examined, Skipped, ReWrapped int
}

// RotateKEK re-wraps every data key under r.To. It is safe to run
// repeatedly: a key already recorded against r.To is skipped, so an
// interrupted run is finished by running it again. It stops at the first
// failure rather than grinding on, because the usual cause is a master
// key that is misconfigured for every key alike, and returns the report
// so far alongside the error.
func RotateKEK(ctx context.Context, r KEKRotation) (KEKReport, error) {
	var rep KEKReport
	if r.Store == nil || r.To == nil {
		return rep, errors.New("kek rotation needs a store and a target key")
	}
	log := loggerOr(r.Log)

	// The target doubles as an unwrapper so that a run interrupted after
	// some keys moved can read those keys back.
	unwrap := map[string]KEK{r.To.Ref(): r.To}
	for _, k := range r.From {
		if k != nil {
			unwrap[k.Ref()] = k
		}
	}

	keys, err := r.Store.ListDataKeys(ctx)
	if err != nil {
		return rep, fmt.Errorf("list data keys: %w", err)
	}
	newRef := r.To.Ref()
	for _, dk := range keys {
		if err := ctx.Err(); err != nil {
			return rep, fmt.Errorf("kek rotation stopped after %d of %d keys: %w", rep.Examined, len(keys), err)
		}
		rep.Examined++
		if dk.KEKRef == newRef {
			rep.Skipped++
			continue
		}
		old, ok := unwrap[dk.KEKRef]
		if !ok {
			// The same key in another region: a restore elsewhere moves
			// its data keys onto the reference this region spells.
			old, ok = relatedOpener(dk.KEKRef, r.To, r.From)
		}
		if !ok {
			return rep, fmt.Errorf("data key %x is wrapped by %q, which was not supplied to the rotation", dk.ID[:4], dk.KEKRef)
		}
		if err := rewrapOne(ctx, r.Store, dk, old, r.To); err != nil {
			return rep, err
		}
		rep.ReWrapped++
		log.InfoContext(ctx, "data key re-wrapped", "key_id", fmt.Sprintf("%x", dk.ID[:4]), "scope", dk.Scope, "from", dk.KEKRef, "to", newRef)
	}
	return rep, nil
}

func rewrapOne(ctx context.Context, store KEKRotationStore, dk *DataKey, old, to KEK) error {
	dek, err := old.Unwrap(ctx, dk.Wrapped)
	if err != nil {
		return fmt.Errorf("unwrap data key %x under %s: %w", dk.ID[:4], old.Ref(), err)
	}
	defer zeroKey(dek)
	wrapped, err := to.Wrap(ctx, dek)
	if err != nil {
		return fmt.Errorf("wrap data key %x under %s: %w", dk.ID[:4], to.Ref(), err)
	}
	// Prove the new blob opens before the old wrapping is overwritten. A
	// master key that encrypts happily but cannot decrypt — an IAM policy
	// granting kms:Encrypt only, a key pending deletion, an encryption
	// context that differs between two pods — would otherwise silently
	// destroy every secret under this data key, and the row being
	// overwritten is the only copy of the wrapping.
	check, err := to.Unwrap(ctx, wrapped)
	if err != nil {
		return fmt.Errorf("verify re-wrapped data key %x under %s: %w", dk.ID[:4], to.Ref(), err)
	}
	defer zeroKey(check)
	if !bytes.Equal(check, dek) {
		return fmt.Errorf("data key %x does not round-trip under %s", dk.ID[:4], to.Ref())
	}
	return store.ReWrapDataKey(ctx, dk.ID, to.Ref(), wrapped)
}

// ---------------------------------------------------------------------------
// Data key rotation

// DataKeyRotationStore is the store surface re-sealing needs on top of
// the everyday KeyStore.
type DataKeyRotationStore interface {
	KeyStore
	// SetDataKeyStatus moves a key between active, decrypt_only and
	// retired. Only one key per scope may be active, so demoting the
	// current key is what allows a new one to be minted.
	SetDataKeyStatus(ctx context.Context, id [keyIDLen]byte, status string) error
}

// ReSealTarget names one sealed column. The caller supplies the set of
// targets rather than this package hard-coding it, because the sealed
// columns belong to other packages' tables: connector credentials,
// connector tokens, identity provider secrets, audit exporter configs,
// signing keys. A list here would go stale the first time a feature adds
// a sealed column, and it would be stale silently — rotation would report
// success having left the new column on the old key.
type ReSealTarget struct {
	Table  string
	Column string
	// IDColumn orders and addresses the rows. It may be an expression
	// rather than a column, because not every sealed row is addressed by
	// a single column: a connector credential is one row of a composite
	// key and its binding names both halves. Whatever it yields must be
	// the same string the owning package puts in AAD.RowID, so that a
	// cursor and a binding are the one value and a re-seal cannot bind a
	// row to a name the read path will not reproduce.
	IDColumn string
}

func (t ReSealTarget) String() string { return t.Table + "." + t.Column }

// SealedRow is one row of a ReSealTarget.
type SealedRow struct {
	// Cursor is the row's id-column value. Rotation asks for rows after
	// it, so batches walk the table once in a stable order.
	Cursor string
	// AAD is the row's binding, built exactly as the owning package builds
	// it. The caller fills it because only the owner knows the convention:
	// some rows use the primary key, connector credentials use
	// "<connector id>/<name>", and a re-seal that guessed wrong would
	// produce a row nothing can open.
	AAD AAD
	// Value is the sealed column.
	Value []byte
}

// RowStore reads and writes the sealed columns of a target. The caller
// implements it over its own tables and its own tenant transaction, which
// is also what keeps an org-scoped rotation from touching another org's
// rows.
type RowStore interface {
	// SealedRows returns up to limit rows of t whose id sorts after the
	// cursor, in ascending id order. The first call passes an empty
	// cursor. An implementation may narrow the query to rows sealed under
	// a particular data key; rotation re-checks every row it is given, so
	// returning the whole table is equally correct, only slower.
	SealedRows(ctx context.Context, t ReSealTarget, after string, limit int) ([]SealedRow, error)
	// WriteSealed stores one batch of re-sealed values, in one
	// transaction, and returns how many rows it actually replaced.
	// Batches are independent: a crash between two of them leaves the
	// table half rotated, which the next run finishes.
	//
	// The count is returned rather than assumed because a row read at the
	// start of a batch can be gone by the end of it — a connector deleted
	// while the rotation runs — and a report that counted intentions
	// instead of writes would overstate what moved. An implementation
	// must refuse outright, rather than report, a write that matched more
	// than one row: two rows sharing a cursor means one of them is about
	// to be bound to a name its owner will not reproduce.
	WriteSealed(ctx context.Context, t ReSealTarget, rows []SealedRow) (int, error)
}

// CensusStore counts a target's rows by the data key each one names. It is
// separate from RowStore because it opens nothing: the key id sits in the
// clear at a fixed offset of every ciphertext, so the count is a scan
// rather than a decryption, and both the dry run and the decision to
// retire a superseded key are built on it.
type CensusStore interface {
	KeyCensus(ctx context.Context, t ReSealTarget) (map[[keyIDLen]byte]int, error)
}

// DataKeyRotation configures RotateDataKey.
type DataKeyRotation struct {
	Store  DataKeyRotationStore
	Sealer *Sealer
	Rows   RowStore
	// Scope is the key being rotated, ScopeInstance or ScopeOrg(id).
	Scope   string
	Targets []ReSealTarget
	// Batch is rows per transaction; zero means defaultReSealBatch.
	Batch int
	// ReSealOnly finishes an interrupted run: it re-seals onto the scope's
	// current active key instead of minting another one. Without it a
	// second attempt would mint a second new key and leave the first one
	// behind, half used, for every attempt that failed.
	ReSealOnly bool
	Log        *slog.Logger
}

// DataKeyReport says how far RotateDataKey got.
type DataKeyReport struct {
	OldKeyID, NewKeyID [keyIDLen]byte
	// Scanned counts rows looked at, ReSealed those actually rewritten.
	Scanned, ReSealed int
	// Targets breaks the same counts down per table, which is what an
	// operator reads: a total says a rotation ran, a breakdown says which
	// tables it actually reached.
	Targets []TargetReport
}

// TargetReport is one sealed column's share of a rotation. Rows that were
// neither re-sealed nor empty were already on the new key, which is what
// a resumed run is mostly made of.
type TargetReport struct {
	Target            string
	Scanned, ReSealed int
	// Empty counts rows whose sealed column holds nothing. A nullable
	// sealed column is not a fault: an identity provider configured
	// against a public client has no secret to seal.
	Empty int
	// Vanished counts rows that disappeared between being read and being
	// written, which a connector deleted mid-rotation does.
	Vanished int
}

// RotateDataKey mints a new data key for a scope and re-seals the rows
// that still use an older one, in batches.
//
// A run that stops part way is finished by running it again with
// ReSealOnly set: rows already on the current key are skipped, so only
// the remainder is rewritten and no further key is minted. The old key is
// left decrypt_only rather than retired, because this package cannot know
// whether the caller listed every table that uses it; retiring is a
// deliberate act the operator takes once they are satisfied nothing
// references the old key.
func RotateDataKey(ctx context.Context, r DataKeyRotation) (DataKeyReport, error) {
	var rep DataKeyReport
	switch {
	case r.Store == nil || r.Sealer == nil || r.Rows == nil:
		return rep, errors.New("data key rotation needs a store, a sealer and a row store")
	case r.Scope == "":
		return rep, errors.New("data key rotation needs a scope")
	}
	batch := r.Batch
	if batch <= 0 {
		batch = defaultReSealBatch
	}
	log := loggerOr(r.Log)

	old, ok, err := r.Store.Active(ctx, r.Scope)
	if err != nil {
		return rep, fmt.Errorf("read active data key for %s: %w", r.Scope, err)
	}
	if !ok {
		return rep, fmt.Errorf("no active data key for scope %s", r.Scope)
	}
	rep.OldKeyID = old.ID
	fresh := old
	if !r.ReSealOnly {
		// Demote first: the unique index permits one active key per scope,
		// so the new key cannot exist until the old one steps aside. A
		// crash between the two leaves the scope with no active key, which
		// the next seal repairs by minting one — the same path a brand new
		// scope takes.
		if err := r.Store.SetDataKeyStatus(ctx, old.ID, statusDecryptOnly); err != nil {
			return rep, fmt.Errorf("demote data key %x: %w", old.ID[:4], err)
		}
		if fresh, err = r.Sealer.activeKey(ctx, r.Scope); err != nil {
			return rep, fmt.Errorf("mint data key for %s: %w", r.Scope, err)
		}
	}
	rep.NewKeyID = fresh.ID
	log.InfoContext(ctx, "re-sealing scope", "scope", r.Scope, "resume", r.ReSealOnly,
		"old_key_id", fmt.Sprintf("%x", old.ID[:4]), "new_key_id", fmt.Sprintf("%x", fresh.ID[:4]))

	// Re-seal through a sealer pinned to the two keys already resolved.
	// The shared sealer re-reads the scope's active key from the database
	// on every Seal and the referenced key on every Open, which over a
	// million rows is two million queries for an answer that cannot
	// change during the run.
	//
	// The decrypt-only master keys come across with it. An installation
	// part way through a master key rotation holds data keys under two
	// masters at once, and a pinned sealer that knew only the active one
	// would refuse the very rows this job exists to move.
	pinned := New(r.Sealer.kek, &pinnedKeyStore{active: fresh, inner: r.Store, byID: map[[keyIDLen]byte]*DataKey{}}, r.Sealer.decryptOnly()...)

	for _, t := range r.Targets {
		tr, err := reSealTarget(ctx, r, pinned, t, fresh.ID, batch)
		rep.Scanned += tr.Scanned
		rep.ReSealed += tr.ReSealed
		rep.Targets = append(rep.Targets, tr)
		if err != nil {
			return rep, err
		}
		log.InfoContext(ctx, "target re-sealed", "target", t.String(), "scanned", tr.Scanned,
			"resealed", tr.ReSealed, "empty", tr.Empty, "vanished", tr.Vanished)
	}
	return rep, nil
}

func reSealTarget(ctx context.Context, r DataKeyRotation, sealer *Sealer, t ReSealTarget, current [keyIDLen]byte, batch int) (TargetReport, error) {
	rep := TargetReport{Target: t.String()}
	cursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return rep, fmt.Errorf("re-seal of %s stopped after %d rows: %w", t, rep.Scanned, err)
		}
		rows, err := r.Rows.SealedRows(ctx, t, cursor, batch)
		if err != nil {
			return rep, fmt.Errorf("read %s after %q: %w", t, cursor, err)
		}
		if len(rows) == 0 {
			return rep, nil
		}
		out := make([]SealedRow, 0, len(rows))
		for _, row := range rows {
			cursor = row.Cursor
			rep.Scanned++
			// A sealed column that is nullable holds nothing when the
			// feature it belongs to is unused: an identity provider
			// registered as a public client has no secret. There is no
			// ciphertext to bring forward and no fault to report, but the
			// header check below would call an empty value malformed and
			// abandon the whole rotation over it.
			if len(row.Value) == 0 {
				rep.Empty++
				continue
			}
			id, err := KeyID(row.Value)
			if err != nil {
				return rep, fmt.Errorf("read key id of %s row %q: %w", t, row.Cursor, err)
			}
			// Anything not already on the current key is brought forward,
			// which sweeps up rows left on a key two generations old by an
			// earlier interrupted rotation as well as the one being retired.
			if id == current {
				continue
			}
			resealed, err := reSealRow(ctx, sealer, r.Scope, t, row)
			if err != nil {
				return rep, err
			}
			row.Value = resealed
			out = append(out, row)
		}
		if len(out) > 0 {
			written, err := r.Rows.WriteSealed(ctx, t, out)
			if err != nil {
				return rep, fmt.Errorf("write %s batch ending %q: %w", t, cursor, err)
			}
			rep.ReSealed += written
			rep.Vanished += len(out) - written
		}
		if len(rows) < batch {
			return rep, nil
		}
	}
}

// reSealRow opens one value under whichever key sealed it and seals it
// again under the scope's current one, proving the result opens before
// handing it back to be written.
//
// The proof is the point. The row about to be overwritten holds the only
// copy of the ciphertext, and a value that seals but does not open — a
// binding assembled differently on the two paths, a data key whose
// material is not what its id claims, a GCM tag lost to a short write —
// would otherwise be found by the first request that needed it, days
// later, with nothing left to recover it from. Re-opening costs one more
// pass over bytes already in memory under a key already unwrapped, which
// is nothing set against a credential nobody can read again.
func reSealRow(ctx context.Context, sealer *Sealer, scope string, t ReSealTarget, row SealedRow) ([]byte, error) {
	pt, err := sealer.Open(ctx, row.Value, row.AAD)
	if err != nil {
		return nil, fmt.Errorf("open %s row %q: %w", t, row.Cursor, err)
	}
	defer zeroKey(pt)
	ct, err := sealer.Seal(ctx, scope, pt, row.AAD)
	if err != nil {
		return nil, fmt.Errorf("re-seal %s row %q: %w", t, row.Cursor, err)
	}
	check, err := sealer.Open(ctx, ct, row.AAD)
	if err != nil {
		return nil, fmt.Errorf("re-sealed %s row %q does not open again: %w", t, row.Cursor, err)
	}
	defer zeroKey(check)
	if !bytes.Equal(check, pt) {
		return nil, fmt.Errorf("re-sealed %s row %q opens to different bytes", t, row.Cursor)
	}
	return ct, nil
}

// ---------------------------------------------------------------------------
// Retirement

// RetirementStore is what retiring a superseded data key needs.
type RetirementStore interface {
	// ListDataKeys returns every data key, of every scope and status.
	ListDataKeys(ctx context.Context) ([]*DataKey, error)
	SetDataKeyStatus(ctx context.Context, id [keyIDLen]byte, status string) error
}

// Retirement configures RetireSuperseded.
type Retirement struct {
	Store   RetirementStore
	Census  CensusStore
	Scope   string
	Targets []ReSealTarget
	Log     *slog.Logger
}

// RetirementReport says which keys were retired and which were held back.
type RetirementReport struct {
	Retired []string
	// Held maps a key id, abbreviated as the logs abbreviate it, to the
	// number of rows still sealed under it.
	Held map[string]int
}

// RetireSuperseded marks a scope's decrypt-only keys retired, but only
// those no row still names.
//
// Retirement is bookkeeping rather than destruction — a retired key is
// still returned by the store and still opens a restored backup — so the
// cost of being wrong is low and the value of being right is that the
// status column means what it says. A key left decrypt_only for ever
// because one forgotten row referenced it is the honest outcome, and the
// count of those rows is what the operator needs to go and look at.
//
// The census is taken across the targets the caller supplies, which is the
// same list the rotation ran on. A caller that omits a table would retire
// a key that table still uses; that is why the command checks its target
// list against the schema before it runs either one.
func RetireSuperseded(ctx context.Context, r Retirement) (RetirementReport, error) {
	rep := RetirementReport{Held: map[string]int{}}
	if r.Store == nil || r.Census == nil {
		return rep, errors.New("retirement needs a store and a census")
	}
	if r.Scope == "" {
		return rep, errors.New("retirement needs a scope")
	}
	log := loggerOr(r.Log)

	keys, err := r.Store.ListDataKeys(ctx)
	if err != nil {
		return rep, fmt.Errorf("list data keys: %w", err)
	}
	candidates := make([]*DataKey, 0, len(keys))
	for _, dk := range keys {
		if dk.Scope == r.Scope && dk.Status == statusDecryptOnly {
			candidates = append(candidates, dk)
		}
	}
	if len(candidates) == 0 {
		return rep, nil
	}

	// One census over every target, then one decision per key: the counts
	// have to come from a single pass, because asking per key would let a
	// row move between two questions and answer no to both.
	total := map[[keyIDLen]byte]int{}
	for _, t := range r.Targets {
		c, err := r.Census.KeyCensus(ctx, t)
		if err != nil {
			return rep, fmt.Errorf("census of %s: %w", t, err)
		}
		for id, n := range c {
			total[id] += n
		}
	}
	for _, dk := range candidates {
		short := fmt.Sprintf("%x", dk.ID[:4])
		if n := total[dk.ID]; n > 0 {
			rep.Held[short] = n
			log.InfoContext(ctx, "data key kept decrypt-only", "key_id", short, "scope", dk.Scope, "rows", n)
			continue
		}
		if err := r.Store.SetDataKeyStatus(ctx, dk.ID, statusRetired); err != nil {
			return rep, fmt.Errorf("retire data key %s: %w", short, err)
		}
		rep.Retired = append(rep.Retired, short)
		log.InfoContext(ctx, "data key retired", "key_id", short, "scope", dk.Scope)
	}
	return rep, nil
}

// ---------------------------------------------------------------------------
// Helpers

// pinnedKeyStore serves the keys a rotation already resolved and caches
// anything else it is asked for. It is used by the rotation loop alone,
// so it needs no locking; the sealer built over it is not shared.
type pinnedKeyStore struct {
	active *DataKey
	inner  KeyStore
	byID   map[[keyIDLen]byte]*DataKey
}

func (p *pinnedKeyStore) Active(ctx context.Context, scope string) (*DataKey, bool, error) {
	if scope == p.active.Scope {
		return p.active, true, nil
	}
	return p.inner.Active(ctx, scope)
}

func (p *pinnedKeyStore) Get(ctx context.Context, id [keyIDLen]byte) (*DataKey, bool, error) {
	if dk, ok := p.byID[id]; ok {
		return dk, true, nil
	}
	dk, ok, err := p.inner.Get(ctx, id)
	if err != nil || !ok {
		return nil, ok, err
	}
	p.byID[id] = dk
	return dk, true, nil
}

func (p *pinnedKeyStore) Put(ctx context.Context, k *DataKey) error { return p.inner.Put(ctx, k) }

// decryptOnly lists the master keys a sealer will open a data key with but
// never wrap one under. It lives here rather than beside the sealer
// because rotation is the only caller: everything else is handed the set
// once, at construction, and never has to take it apart again.
func (s *Sealer) decryptOnly() []KEK {
	if len(s.older) == 0 {
		return nil
	}
	out := make([]KEK, 0, len(s.older))
	for _, k := range s.older {
		out = append(out, k)
	}
	return out
}

// zeroKey overwrites key material the moment it stops being needed, so a
// core dump or a swapped page taken later does not hand over a data key.
func zeroKey(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func loggerOr(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.New(slog.DiscardHandler)
}

// relatedOpener finds, among the target and the decrypt-only keys, one
// that opens what ref wrapped although it spells its reference otherwise.
func relatedOpener(ref string, to KEK, from []KEK) (KEK, bool) {
	for _, k := range append([]KEK{to}, from...) {
		if o, ok := openerFor(k, ref); ok {
			return o, true
		}
	}
	return nil, false
}
