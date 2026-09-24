// Package mcpauth authenticates MCP clients: API keys now, the OAuth 2.1
// authorization server in M2.
package mcpauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
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

// Errors.
var (
	ErrInvalidKey = errors.New("invalid API key")
	ErrKeyExpired = errors.New("API key expired")
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
	err = k.DB.Tx(tenant.WithOrg(ctx, in.OrgID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO api_keys (id, organization_id, principal_kind, principal_id, name, prefix, hash, scopes, server_id, expires_at, rotated_from, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),$10,NULLIF($11,''),NULLIF($12,''))`,
			rec.ID, rec.OrgID, rec.PrincipalKind, rec.PrincipalID, rec.Name, rec.Prefix, hash, rec.Scopes, rec.ServerID, rec.ExpiresAt, rec.RotatedFrom, in.CreatedBy)
		return err
	})
	if err != nil {
		return nil, "", err
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
			return pgx.ErrNoRows
		}
		return nil
	})
}

// Rotate creates a replacement and gives the old key a grace period.
func (k *Keys) Rotate(ctx context.Context, orgID, id, principalID string, grace time.Duration) (*APIKey, string, error) {
	var old APIKey
	err := k.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT id, principal_kind, principal_id, name, scopes, COALESCE(server_id,''), expires_at FROM api_keys WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL`, id, orgID).
			Scan(&old.ID, &old.PrincipalKind, &old.PrincipalID, &old.Name, &old.Scopes, &old.ServerID, &old.ExpiresAt); err != nil {
			return err
		}
		if principalID != "" && old.PrincipalID != principalID {
			return pgx.ErrNoRows
		}
		if grace <= 0 {
			grace = 24 * time.Hour
		}
		_, err := tx.Exec(ctx, `UPDATE api_keys SET expires_at = LEAST(COALESCE(expires_at, 'infinity'), $2::timestamptz) WHERE id = $1`, id, k.now().Add(grace))
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return k.Create(ctx, CreateInput{OrgID: orgID, PrincipalKind: old.PrincipalKind, PrincipalID: old.PrincipalID, Name: old.Name, Scopes: old.Scopes, ServerID: old.ServerID, CreatedBy: principalID, RotatedFrom: old.ID})
}
