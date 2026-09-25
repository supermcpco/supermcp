// Package mcpauth authenticates MCP clients: API keys, and the OAuth 2.1
// authorization server that issues their access tokens.
package mcpauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/tenant"
)

const (
	keyPrefix = "smk_"
	prefixLen = 12
)

// DefaultRotationGrace is how long a rotated key keeps working when the
// caller does not say.
const DefaultRotationGrace = 24 * time.Hour

// MaxRotationGrace caps how long a rotated key keeps working. Two live keys
// for one principal is a window a holder of the old key shares, so it is
// kept short.
const MaxRotationGrace = 7 * 24 * time.Hour

// Errors.
var (
	ErrInvalidKey = errors.New("invalid API key")
	ErrKeyExpired = errors.New("API key expired")

	// ErrKeyNotFound is returned when the key does not exist or is not the
	// caller's to change.
	ErrKeyNotFound = errors.New("API key not found")
	// ErrRotateRevoked refuses to rotate a revoked key.
	ErrRotateRevoked = errors.New("API key is revoked and cannot be rotated; create a new key")
	// ErrRotateExpired refuses to rotate a key that has already expired.
	ErrRotateExpired = errors.New("API key has expired and cannot be rotated; create a new key")
	// ErrRotateTwice refuses to rotate a key that already has a replacement.
	ErrRotateTwice = errors.New("API key has already been rotated; rotate its replacement instead")
	// ErrGraceRange rejects a grace period outside [0, MaxRotationGrace].
	ErrGraceRange = errors.New("grace must be between 0 and 7 days")
)

// APIKey is the stored record (never the secret).
type APIKey struct {
	ID            string
	OrgID         string
	PrincipalKind string
	PrincipalID   string
	Name          string
	Prefix        string
	Scopes        []string
	ServerID      string
	ExpiresAt     *time.Time
	LastUsedAt    *time.Time
	RevokedAt     *time.Time
	RotatedFrom   string
	CreatedAt     time.Time
}

// Keys manages API keys.
type Keys struct {
	DB         *tenant.DB
	DefaultTTL time.Duration // 0 = no expiry
	mu         sync.Mutex
	lastTouch  map[string]time.Time
	now        func() time.Time
	newID      func() string
}

// New builds the key service.
func New(db *tenant.DB, newID func() string) *Keys {
	return &Keys{DB: db, DefaultTTL: 90 * 24 * time.Hour, lastTouch: map[string]time.Time{}, now: time.Now, newID: newID}
}

// Generate mints a key: smk_ + 12-char prefix + 43-char secret. Only the
// sha256 of the full string is stored.
func Generate() (full, prefix string, hash []byte, err error) {
	raw := make([]byte, 9+32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", nil, err
	}
	prefix = base64.RawURLEncoding.EncodeToString(raw[:9])[:prefixLen]
	secret := base64.RawURLEncoding.EncodeToString(raw[9:])
	full = keyPrefix + prefix + secret
	sum := sha256.Sum256([]byte(full))
	return full, prefix, sum[:], nil
}

// CreateInput describes a new key.
type CreateInput struct {
	OrgID         string
	PrincipalKind string
	PrincipalID   string
	Name          string
	Scopes        []string
	ServerID      string
	TTL           time.Duration // 0 = DefaultTTL; negative = never expires
	CreatedBy     string
	RotatedFrom   string
}

// Create stores a key and returns the record plus the one-time secret.
func (k *Keys) Create(ctx context.Context, in CreateInput) (*APIKey, string, error) {
	if in.Name == "" {
		return nil, "", errors.New("name is required")
	}
	if len(in.Scopes) == 0 {
		in.Scopes = []string{authz.ScopeToolsRead, authz.ScopeToolsInvoke}
	}
	for _, s := range in.Scopes {
		switch s {
		case authz.ScopeToolsRead, authz.ScopeToolsInvoke, authz.ScopeOrg, authz.ScopeSCIM:
		default:
			return nil, "", errors.New("unknown scope " + s)
		}
	}
	var rec *APIKey
	var full string
	err := k.DB.Tx(tenant.WithOrg(ctx, in.OrgID), func(tx pgx.Tx) error {
		var err error
		rec, full, err = k.insert(ctx, tx, in)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return rec, full, nil
}

// insert mints a key and stores it in tx. The caller has validated in.
func (k *Keys) insert(ctx context.Context, tx pgx.Tx, in CreateInput) (*APIKey, string, error) {
	full, prefix, hash, err := Generate()
	if err != nil {
		return nil, "", err
	}
	rec := &APIKey{ID: k.newID(), OrgID: in.OrgID, PrincipalKind: in.PrincipalKind, PrincipalID: in.PrincipalID,
		Name: in.Name, Prefix: prefix, Scopes: in.Scopes, ServerID: in.ServerID, RotatedFrom: in.RotatedFrom, CreatedAt: k.now()}
	ttl := in.TTL
	if ttl == 0 {
		ttl = k.DefaultTTL
	}
	if ttl > 0 {
		t := k.now().Add(ttl)
		rec.ExpiresAt = &t
	}
	_, err = tx.Exec(ctx, `INSERT INTO api_keys (id, organization_id, principal_kind, principal_id, name, prefix, hash, scopes, server_id, expires_at, rotated_from, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),$10,NULLIF($11,''),NULLIF($12,''))`,
		rec.ID, rec.OrgID, rec.PrincipalKind, rec.PrincipalID, rec.Name, rec.Prefix, hash, rec.Scopes, rec.ServerID, rec.ExpiresAt, rec.RotatedFrom, in.CreatedBy)
	if err != nil {
		return nil, "", fmt.Errorf("insert api key: %w", err)
	}
	return rec, full, nil
}

// Authenticate resolves a presented key to a principal. It runs before a
// tenant is known, through the auth_api_key SECURITY DEFINER function.
func (k *Keys) Authenticate(ctx context.Context, presented string, ip string) (*authz.Principal, error) {
	if !strings.HasPrefix(presented, keyPrefix) || len(presented) < len(keyPrefix)+prefixLen+20 {
		return nil, ErrInvalidKey
	}
	prefix := presented[len(keyPrefix) : len(keyPrefix)+prefixLen]
	var rec APIKey
	var hash []byte
	err := k.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, organization_id, principal_kind, principal_id, hash, scopes, COALESCE(server_id,''), expires_at, revoked_at FROM auth_api_key($1)`, prefix).
			Scan(&rec.ID, &rec.OrgID, &rec.PrincipalKind, &rec.PrincipalID, &hash, &rec.Scopes, &rec.ServerID, &rec.ExpiresAt, &rec.RevokedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidKey
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(presented))
	if subtle.ConstantTimeCompare(sum[:], hash) != 1 {
		return nil, ErrInvalidKey
	}
	if rec.RevokedAt != nil {
		return nil, ErrInvalidKey
	}
	if rec.ExpiresAt != nil && rec.ExpiresAt.Before(k.now()) {
		return nil, ErrKeyExpired
	}
	k.touch(ctx, &rec, ip)
	kind := authz.KindAPIKey
	if rec.PrincipalKind == "service_account" {
		kind = authz.KindServiceAccount
	}
	return &authz.Principal{Kind: kind, ID: rec.PrincipalID, OrgID: rec.OrgID, APIKeyID: rec.ID, ServerID: rec.ServerID, Scopes: rec.Scopes, AuthMethod: "api_key"}, nil
}

// touch records last use at most once per five minutes per key.
func (k *Keys) touch(ctx context.Context, rec *APIKey, ip string) {
	k.mu.Lock()
	last, ok := k.lastTouch[rec.ID]
	if ok && k.now().Sub(last) < 5*time.Minute {
		k.mu.Unlock()
		return
	}
	k.lastTouch[rec.ID] = k.now()
	k.mu.Unlock()
	var addr *netip.Addr
	if a, err := netip.ParseAddr(ip); err == nil {
		addr = &a
	}
	_ = k.DB.Tx(tenant.WithOrg(ctx, rec.OrgID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE api_keys SET last_used_at = now(), last_used_ip = $2 WHERE id = $1`, rec.ID, addr)
		return err
	})
}

// List returns the caller's keys, or all org keys when all is true.
func (k *Keys) List(ctx context.Context, orgID, principalID string, all bool) ([]APIKey, error) {
	var out []APIKey
	err := k.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		q := `SELECT id, organization_id, principal_kind, principal_id, name, prefix, scopes, COALESCE(server_id,''), expires_at, last_used_at, revoked_at, COALESCE(rotated_from,''), created_at
			FROM api_keys WHERE organization_id = $1 AND ($2 OR principal_id = $3) ORDER BY created_at DESC`
		rows, err := tx.Query(ctx, q, orgID, all, principalID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r APIKey
			if err := rows.Scan(&r.ID, &r.OrgID, &r.PrincipalKind, &r.PrincipalID, &r.Name, &r.Prefix, &r.Scopes, &r.ServerID, &r.ExpiresAt, &r.LastUsedAt, &r.RevokedAt, &r.RotatedFrom, &r.CreatedAt); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if out == nil {
		out = []APIKey{}
	}
	return out, err
}

// Revoke marks a key revoked. self restricts to the caller's own keys.
func (k *Keys) Revoke(ctx context.Context, orgID, id, principalID string, self bool, reason string) error {
	return k.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE api_keys SET revoked_at = now(), revoked_reason = $4 WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL AND ($3 = '' OR principal_id = $3)`,
			id, orgID, map[bool]string{true: principalID, false: ""}[self], reason)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			// Unknown, someone else's, or already revoked: the caller
			// learns no more than that there is nothing here to revoke.
			return ErrKeyNotFound
		}
		return nil
	})
}

// RotateInput names the key to rotate and who is rotating it.
type RotateInput struct {
	OrgID   string
	ID      string
	ActorID string
	// Self restricts the rotation to keys whose principal is ActorID.
	Self bool
	// Grace is how long the old key keeps working, in [0, MaxRotationGrace].
	// Zero stops it at once.
	Grace time.Duration
}

// Rotation is the outcome of Rotate.
type Rotation struct {
	Key    *APIKey
	Secret string
	// PreviousExpiresAt is when the old key stops working.
	PreviousExpiresAt time.Time
}

// Rotate replaces a key: the replacement gets the old key's principal,
// name, scopes and server, and the old key's expiry is brought forward to
// now+grace (never pushed back). Both happen in one transaction, so a
// failure leaves the old key exactly as it was. The old row is locked
// while this runs, so of two concurrent rotations of one key, one wins and
// the other gets ErrRotateTwice.
func (k *Keys) Rotate(ctx context.Context, in RotateInput) (*Rotation, error) {
	if in.Grace < 0 || in.Grace > MaxRotationGrace {
		return nil, ErrGraceRange
	}
	var out Rotation
	err := k.DB.Tx(tenant.WithOrg(ctx, in.OrgID), func(tx pgx.Tx) error {
		var old APIKey
		err := tx.QueryRow(ctx, `SELECT id, principal_kind, principal_id, name, scopes, COALESCE(server_id,''), expires_at, revoked_at
			FROM api_keys WHERE id = $1 AND organization_id = $2 AND ($3 = '' OR principal_id = $3) FOR UPDATE`,
			in.ID, in.OrgID, selfFilter(in.Self, in.ActorID)).
			Scan(&old.ID, &old.PrincipalKind, &old.PrincipalID, &old.Name, &old.Scopes, &old.ServerID, &old.ExpiresAt, &old.RevokedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrKeyNotFound
		}
		if err != nil {
			return fmt.Errorf("lock api key: %w", err)
		}
		now := k.now()
		if old.RevokedAt != nil {
			return ErrRotateRevoked
		}
		if old.ExpiresAt != nil && !old.ExpiresAt.After(now) {
			return ErrRotateExpired
		}
		// Read after taking the lock: under read committed a rotation that
		// committed while this one waited is visible here as its new row.
		var rotated bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM api_keys WHERE rotated_from = $1)`, old.ID).Scan(&rotated); err != nil {
			return fmt.Errorf("check replacement: %w", err)
		}
		if rotated {
			return ErrRotateTwice
		}
		if err := tx.QueryRow(ctx, `UPDATE api_keys SET expires_at = LEAST(COALESCE(expires_at, 'infinity'), $2::timestamptz) WHERE id = $1 RETURNING expires_at`,
			old.ID, now.Add(in.Grace)).Scan(&out.PreviousExpiresAt); err != nil {
			return fmt.Errorf("shorten old key: %w", err)
		}
		out.Key, out.Secret, err = k.insert(ctx, tx, CreateInput{OrgID: in.OrgID, PrincipalKind: old.PrincipalKind, PrincipalID: old.PrincipalID,
			Name: old.Name, Scopes: old.Scopes, ServerID: old.ServerID, CreatedBy: in.ActorID, RotatedFrom: old.ID})
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// selfFilter is the principal a query is restricted to: the actor when
// self, nobody (every key in the org) otherwise.
func selfFilter(self bool, actorID string) string {
	if self {
		return actorID
	}
	return ""
}
