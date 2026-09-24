package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// KeyStore persists envelope data keys in data_keys. Org-scoped keys are
// read and written through the tenant transaction; the instance scope goes
// through Bypass because no tenant owns it.
type KeyStore struct {
	DB *tenant.DB
}

var (
	_ secrets.KeyStore             = (*KeyStore)(nil)
	_ secrets.KEKRotationStore     = (*KeyStore)(nil)
	_ secrets.DataKeyRotationStore = (*KeyStore)(nil)
)

func (k *KeyStore) run(ctx context.Context, scope string, fn func(pgx.Tx) error) error {
	if _, ok := tenant.OrgID(ctx); ok && scope != secrets.ScopeInstance {
		return k.DB.Tx(ctx, fn)
	}
	return k.DB.Bypass(ctx, "data-key:"+scope, fn)
}

func (k *KeyStore) Active(ctx context.Context, scope string) (*secrets.DataKey, bool, error) {
	var dk secrets.DataKey
	var id []byte
	found := false
	err := k.run(ctx, scope, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id, scope, kek_ref, wrapped, status FROM data_keys WHERE scope = $1 AND status = 'active'`, scope).
			Scan(&id, &dk.Scope, &dk.KEKRef, &dk.Wrapped, &dk.Status)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	if err != nil || !found {
		return nil, false, err
	}
	copy(dk.ID[:], id)
	return &dk, true, nil
}

func (k *KeyStore) Get(ctx context.Context, id [16]byte) (*secrets.DataKey, bool, error) {
	var dk secrets.DataKey
	var raw []byte
	found := false
	// Lookup by id may come from any scope the caller can see; use the
	// tenant tx when one is set, else bypass (instance keys).
	fn := func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id, scope, kek_ref, wrapped, status FROM data_keys WHERE id = $1`, id[:]).
			Scan(&raw, &dk.Scope, &dk.KEKRef, &dk.Wrapped, &dk.Status)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	}
	var err error
	if _, ok := tenant.OrgID(ctx); ok {
		err = k.DB.Tx(ctx, fn)
	} else {
		err = k.DB.Bypass(ctx, "data-key:get", fn)
	}
	if err != nil || !found {
		return nil, false, err
	}
	copy(dk.ID[:], raw)
	return &dk, true, nil
}

func (k *KeyStore) Put(ctx context.Context, dk *secrets.DataKey) error {
	return k.run(ctx, dk.Scope, func(tx pgx.Tx) error {
		// The partial unique index on (scope) WHERE status='active' makes a
		// concurrent first-use race lose cleanly; the caller re-reads.
		_, err := tx.Exec(ctx, `INSERT INTO data_keys (id, scope, kek_ref, wrapped, status) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT DO NOTHING`, dk.ID[:], dk.Scope, dk.KEKRef, dk.Wrapped, dk.Status)
		return err
	})
}

// ---------------------------------------------------------------------------
// Rotation. Every method below runs through Bypass: a rotation spans the
// whole installation, and the policy on data_keys admits one tenant's
// scope at a time, so under row-level security a rotation would silently
// see and move only the keys of whichever org happened to be in the
// context. Silently is the problem — it would report success having left
// every other tenant on the old master key.

// ListDataKeys returns every data key, of every scope and status.
// Retired keys are included because they are still the only way to open
// a restored backup.
func (k *KeyStore) ListDataKeys(ctx context.Context) ([]*secrets.DataKey, error) {
	var out []*secrets.DataKey
	err := k.DB.Bypass(ctx, "data-key:list", func(tx pgx.Tx) error {
		out = nil
		rows, err := tx.Query(ctx, `SELECT id, scope, kek_ref, wrapped, status FROM data_keys ORDER BY created_at, id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var dk secrets.DataKey
			var id []byte
			if err := rows.Scan(&id, &dk.Scope, &dk.KEKRef, &dk.Wrapped, &dk.Status); err != nil {
				return err
			}
			copy(dk.ID[:], id)
			out = append(out, &dk)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReWrapDataKey replaces a key's wrapped material and the reference to
// the master key that wrapped it.
//
// One statement, both columns: the wrapped blob only means anything
// alongside the reference that says which master key opens it, so a
// process interrupted between two updates would leave a row naming one
// key and holding a blob made by another — unreadable, and with the only
// copy of the previous wrapping already overwritten. Updating them
// together makes an interrupted rotation resumable instead.
func (k *KeyStore) ReWrapDataKey(ctx context.Context, id [16]byte, kekRef string, wrapped []byte) error {
	if kekRef == "" || len(wrapped) == 0 {
		return errors.New("re-wrap needs a kek reference and wrapped material")
	}
	return k.DB.Bypass(ctx, "data-key:rewrap", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE data_keys SET kek_ref = $2, wrapped = $3 WHERE id = $1`, id[:], kekRef, wrapped)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("no data key %x", id[:4])
		}
		return nil
	})
}

// SetDataKeyStatus moves a key between active, decrypt_only and retired.
// The partial unique index allows one active key per scope, so demoting
// the current key is what lets a replacement be minted.
func (k *KeyStore) SetDataKeyStatus(ctx context.Context, id [16]byte, status string) error {
	return k.DB.Bypass(ctx, "data-key:status", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE data_keys SET status = $2 WHERE id = $1`, id[:], status)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("no data key %x", id[:4])
		}
		return nil
	})
}
