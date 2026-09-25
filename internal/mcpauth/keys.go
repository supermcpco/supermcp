package mcpauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// Keyring holds the ES256 keys that sign MCP access tokens.
//
// Tokens are asymmetric so a resource server (or a customer's own
// verifier) can check them from the published JWKS without sharing a
// secret. Rotation publishes the next key before it is used, so a client
// that cached the JWKS still verifies tokens after a rotation.
type Keyring struct {
	DB     *tenant.DB
	Sealer *secrets.Sealer
	NewID  func() string
	// Log records rotations. A rotation nobody can see afterwards is a
	// change of signing key that looks like a bug when tokens are
	// investigated. Nil logs nothing.
	Log *slog.Logger

	mu      sync.RWMutex
	loaded  time.Time
	active  *signingKey
	byKID   map[string]*signingKey
	pubJWKS []byte
}

type signingKey struct {
	kid    string
	priv   *ecdsa.PrivateKey
	pubJWK map[string]any
	status string
}

// NewKeyring builds a keyring.
func NewKeyring(db *tenant.DB, sealer *secrets.Sealer, newID func() string) *Keyring {
	return &Keyring{DB: db, Sealer: sealer, NewID: newID, byKID: map[string]*signingKey{}}
}

const keyCacheTTL = time.Minute

// Ensure loads the keys, creating the first one on a fresh instance.
func (k *Keyring) Ensure(ctx context.Context) error {
	k.mu.RLock()
	fresh := time.Since(k.loaded) < keyCacheTTL && k.active != nil
	k.mu.RUnlock()
	if fresh {
		return nil
	}
	if err := k.load(ctx); err != nil {
		return err
	}
	k.mu.RLock()
	has := k.active != nil
	k.mu.RUnlock()
	if has {
		return nil
	}
	if err := k.Rotate(ctx, true); err != nil {
		return err
	}
	return k.load(ctx)
}

func (k *Keyring) load(ctx context.Context) error {
	keys := map[string]*signingKey{}
	var active *signingKey
	var jwks []map[string]any
	err := k.DB.Bypass(ctx, "signing-keys", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT kid, alg, public_jwk, private_enc, status FROM signing_keys WHERE status <> 'retired' ORDER BY created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var kid, alg, status string
			var pub []byte
			var priv []byte
			if err := rows.Scan(&kid, &alg, &pub, &priv, &status); err != nil {
				return err
			}
			var jwk map[string]any
			if err := json.Unmarshal(pub, &jwk); err != nil {
				return err
			}
			sk := &signingKey{kid: kid, pubJWK: jwk, status: status}
			// Only the active key needs its private half in memory.
			if status == "active" {
				pt, err := k.Sealer.Open(ctx, priv, secrets.AAD{Table: "signing_keys", Column: "private_enc", RowID: kid})
				if err != nil {
					return fmt.Errorf("unseal signing key %s: %w", kid, err)
				}
				pk, err := x509.ParseECPrivateKey(pt)
				if err != nil {
					return err
				}
				sk.priv = pk
				active = sk
			}
			keys[kid] = sk
			// "next" is published early so clients cache it before first use.
			if status == "active" || status == "retiring" || status == "next" {
				jwks = append(jwks, jwk)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	doc, err := json.Marshal(map[string]any{"keys": jwks})
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.byKID, k.active, k.pubJWKS, k.loaded = keys, active, doc, time.Now()
	k.mu.Unlock()
	return nil
}

// Rotate mints a new key. When activate is true it becomes active at once
// (first boot); otherwise it is published as "next" and promoted later.
func (k *Keyring) Rotate(ctx context.Context, activate bool) error {
	nk, err := k.mint(ctx)
	if err != nil {
		return err
	}
	status := "next"
	if activate {
		status = "active"
	}
	err = k.DB.Bypass(ctx, "signing-key-rotate", func(tx pgx.Tx) error {
		if activate {
			if _, err := tx.Exec(ctx, `UPDATE signing_keys SET status = 'retiring', retire_at = now() + interval '30 days' WHERE status = 'active'`); err != nil {
				return err
			}
		}
		return nk.insert(ctx, tx, status)
	})
	if err != nil {
		return err
	}
	k.invalidate()
	return nil
}

// newKey is a freshly minted key, sealed and ready to insert.
type newKey struct {
	kid    string
	jwk    []byte
	sealed []byte
}

// mint generates a key pair and seals its private half under the instance
// data key.
func (k *Keyring) mint(ctx context.Context) (newKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return newKey{}, err
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return newKey{}, err
	}
	// Bytes() gives the uncompressed point (0x04 || X || Y); the JWK
	// coordinates are its two halves.
	point, err := priv.PublicKey.Bytes()
	if err != nil {
		return newKey{}, err
	}
	if len(point) != 65 {
		return newKey{}, fmt.Errorf("unexpected public key encoding of %d bytes", len(point))
	}
	x, y := point[1:33], point[33:65]
	thumb := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + b64(x) + `","y":"` + b64(y) + `"}`))
	kid := b64(thumb[:8])
	jwk := map[string]any{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid, "x": b64(x), "y": b64(y)}
	jwkJSON, _ := json.Marshal(jwk)

	sealed, err := k.Sealer.Seal(ctx, secrets.ScopeInstance, der, secrets.AAD{Table: "signing_keys", Column: "private_enc", RowID: kid})
	if err != nil {
		return newKey{}, err
	}
	return newKey{kid: kid, jwk: jwkJSON, sealed: sealed}, nil
}

func (nk newKey) insert(ctx context.Context, tx pgx.Tx, status string) error {
	_, err := tx.Exec(ctx, `INSERT INTO signing_keys (kid, alg, public_jwk, private_enc, status, activated_at)
		VALUES ($1,'ES256',$2,$3,$4, CASE WHEN $4 = 'active' THEN now() END) ON CONFLICT (kid) DO NOTHING`, nk.kid, nk.jwk, nk.sealed, status)
	return err
}

// invalidate makes the next use reload the keys from the table.
func (k *Keyring) invalidate() {
	k.mu.Lock()
	k.loaded = time.Time{}
	k.mu.Unlock()
}

// PrePublish is how long a key is published as "next" before Maintain
// promotes it: long enough for every client that caches the key set to
// have fetched it.
const PrePublish = 24 * time.Hour

// Replacement is what Replace did.
type Replacement struct {
	// KID is the key that signs from now on (revoke) or once promoted.
	KID string
	// Minted is false when a next key was already published and Replace
	// left it as it was.
	Minted bool
	// Active reports that KID is active now rather than waiting as next.
	Active bool
	// PublishedAt is when KID entered the key set.
	PublishedAt time.Time
	// Replaced is the key that was active before, if any.
	Replaced string
	// Retired are the keys taken out of the key set. Only a revoke
	// retires anything.
	Retired []string
}

// Replace starts a replacement of the signing key on demand.
//
// Without revoke it does what Maintain does when the active key comes of
// age: publish a next key, which Maintain promotes once it has been in
// the key set for PrePublish, after which the old key keeps verifying for
// thirty days. A next key already waiting is kept rather than replaced,
// since it is the one clients have been fetching.
//
// With revoke it is the incident path: every key still in the key set is
// retired at once, so the JWKS stops carrying it and Verify refuses what
// it signed, and a new key is active in the same transaction with no
// pre-publish. The keys that were retiring go too. They are sealed the
// same way as the active one, so whatever exposed that one exposed them,
// and they only vouch for tokens signed before the last promotion, which
// have expired unless the promotion was within the hour.
//
// Other replicas notice within keyCacheTTL; a verifier outside the
// instance, when its cached copy of the JWKS expires.
func (k *Keyring) Replace(ctx context.Context, revoke bool) (Replacement, error) {
	// Minted before the transaction because sealing may create the
	// instance data key, which is a transaction of its own. A key minted
	// and then not needed is thrown away unused.
	nk, err := k.mint(ctx)
	if err != nil {
		return Replacement{}, err
	}
	var rep Replacement
	err = k.DB.Bypass(ctx, "signing-key-replace", func(tx pgx.Tx) error {
		rep = Replacement{}
		// FOR UPDATE holds a concurrent Maintain's promotion until this
		// commits, and the promotion then finds no next key to promote.
		rows, err := tx.Query(ctx, `SELECT kid, status, created_at FROM signing_keys
			WHERE status IN ('active','next') ORDER BY created_at FOR UPDATE`)
		if err != nil {
			return err
		}
		var next string
		var nextAt time.Time
		for rows.Next() {
			var kid, status string
			var at time.Time
			if err := rows.Scan(&kid, &status, &at); err != nil {
				rows.Close()
				return err
			}
			switch status {
			case "active":
				rep.Replaced = kid
			case "next":
				next, nextAt = kid, at
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		if !revoke {
			if next != "" {
				rep.KID, rep.PublishedAt = next, nextAt
				return nil
			}
			// With no active key there is no cached key set to protect,
			// and no key to sign with until one is active.
			status := "next"
			if rep.Replaced == "" {
				status = "active"
			}
			if err := nk.insert(ctx, tx, status); err != nil {
				return err
			}
			rep.KID, rep.Minted, rep.Active = nk.kid, true, status == "active"
			return tx.QueryRow(ctx, `SELECT created_at FROM signing_keys WHERE kid = $1`, nk.kid).Scan(&rep.PublishedAt)
		}

		retired, err := tx.Query(ctx, `UPDATE signing_keys SET status = 'retired', retire_at = now()
			WHERE status <> 'retired' RETURNING kid`)
		if err != nil {
			return err
		}
		rep.Retired, err = pgx.CollectRows(retired, pgx.RowTo[string])
		if err != nil {
			return err
		}
		slices.Sort(rep.Retired)
		if err := nk.insert(ctx, tx, "active"); err != nil {
			return err
		}
		rep.KID, rep.Minted, rep.Active = nk.kid, true, true
		return tx.QueryRow(ctx, `SELECT created_at FROM signing_keys WHERE kid = $1`, nk.kid).Scan(&rep.PublishedAt)
	})
	if err != nil {
		return Replacement{}, err
	}
	k.invalidate()
	if k.Log != nil && rep.Minted {
		k.Log.Info("signing key replaced on demand", "kid", rep.KID, "active", rep.Active,
			"replaced", rep.Replaced, "revoked", revoke, "retired", rep.Retired)
	}
	return rep, nil
}

// JWKS returns the public key set.
func (k *Keyring) JWKS(ctx context.Context) ([]byte, error) {
	if err := k.Ensure(ctx); err != nil {
		return nil, err
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.pubJWKS, nil
}

// Sign produces a compact JWS over claims with the active key.
func (k *Keyring) Sign(ctx context.Context, claims map[string]any) (string, error) {
	if err := k.Ensure(ctx); err != nil {
		return "", err
	}
	k.mu.RLock()
	key := k.active
	k.mu.RUnlock()
	if key == nil || key.priv == nil {
		return "", errors.New("no active signing key")
	}
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": key.kid})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64([]byte(header)) + "." + b64(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key.priv, digest[:])
	if err != nil {
		return "", err
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return signingInput + "." + b64(sig), nil
}

// SignDigest signs an opaque value with the active key and returns
// "<kid>:<signature>", so a verifier knows which published key to check it
// against. The audit anchors use it: what is signed there is a chain hash,
// not a set of claims.
func (k *Keyring) SignDigest(ctx context.Context, b []byte) (string, error) {
	if err := k.Ensure(ctx); err != nil {
		return "", err
	}
	k.mu.RLock()
	key := k.active
	k.mu.RUnlock()
	if key == nil || key.priv == nil {
		return "", errors.New("no active signing key")
	}
	digest := sha256.Sum256(b)
	r, s, err := ecdsa.Sign(rand.Reader, key.priv, digest[:])
	if err != nil {
		return "", err
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return key.kid + ":" + b64(sig), nil
}

// VerifyDigest checks a "<kid>:<signature>" value made by SignDigest.
//
// It reads the public key straight from the table, retired keys included:
// an anchor signed two rotations ago must still verify, and a retired key
// is exactly the one the published JWKS no longer carries. It never
// unseals a private key and never creates one, so an offline verifier
// needs only read access to the database.
func (k *Keyring) VerifyDigest(ctx context.Context, b []byte, signed string) error {
	kid, sigB64, ok := strings.Cut(signed, ":")
	if !ok || kid == "" {
		return errors.New("malformed signature: want <kid>:<signature>")
	}
	sig, err := unb64(sigB64)
	if err != nil || len(sig) != 64 {
		return errors.New("malformed signature")
	}
	var pubJSON []byte
	err = k.DB.Bypass(ctx, "signing-key-public", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT public_jwk FROM signing_keys WHERE kid = $1`, kid).Scan(&pubJSON)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("signed by key %s, which this instance has no record of", kid)
	}
	if err != nil {
		return err
	}
	var jwk map[string]any
	if err := json.Unmarshal(pubJSON, &jwk); err != nil {
		return err
	}
	pub, err := publicKeyFromJWK(jwk)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(b)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return fmt.Errorf("signature by key %s does not verify", kid)
	}
	return nil
}

// Verify checks a token's signature and returns its claims. Expiry and
// audience are the caller's business.
func (k *Keyring) Verify(ctx context.Context, token string) (map[string]any, error) {
	if err := k.Ensure(ctx); err != nil {
		return nil, err
	}
	parts := splitN(token, '.', 3)
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	headerJSON, err := unb64(parts[0])
	if err != nil {
		return nil, err
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, err
	}
	if header.Alg != "ES256" {
		return nil, fmt.Errorf("unsupported algorithm %q", header.Alg)
	}
	k.mu.RLock()
	key := k.byKID[header.Kid]
	k.mu.RUnlock()
	if key == nil {
		// A token signed by a key this process has not seen yet.
		if err := k.load(ctx); err != nil {
			return nil, err
		}
		k.mu.RLock()
		key = k.byKID[header.Kid]
		k.mu.RUnlock()
	}
	if key == nil {
		return nil, errors.New("unknown signing key")
	}
	pub, err := publicKeyFromJWK(key.pubJWK)
	if err != nil {
		return nil, err
	}
	sig, err := unb64(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, errors.New("malformed signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, errors.New("signature does not verify")
	}
	payload, err := unb64(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func publicKeyFromJWK(jwk map[string]any) (*ecdsa.PublicKey, error) {
	xs, _ := jwk["x"].(string)
	ys, _ := jwk["y"].(string)
	xb, err := unb64(xs)
	if err != nil {
		return nil, err
	}
	yb, err := unb64(ys)
	if err != nil {
		return nil, err
	}
	if len(xb) != 32 || len(yb) != 32 {
		return nil, errors.New("malformed JWK coordinates")
	}
	point := append([]byte{0x04}, append(xb, yb...)...)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func splitN(s string, sep byte, n int) []string {
	out := make([]string, 0, n)
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// Maintain moves the keyring along one step: publish the next key when the
// active one is old, promote a next key that has been published long
// enough for every client to have fetched it, and retire what is past its
// date. It is safe to call often and does nothing most of the time.
//
// The gap between publishing and promoting is what keeps a verifier that
// cached the key set before the rotation from rejecting tokens signed
// after it.
func (k *Keyring) Maintain(ctx context.Context) error {
	const maxAge = 90 * 24 * time.Hour
	var (
		activeAge  time.Duration
		nextAge    time.Duration
		hasActive  bool
		hasNext    bool
		nextKID    string
		activeKID  string
		retireSome bool
	)
	err := k.DB.Bypass(ctx, "signing-key-maintain", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT kid, status, COALESCE(activated_at, created_at) FROM signing_keys
			WHERE status IN ('active','next')`)
		if err != nil {
			return err
		}
		defer rows.Close()
		now := time.Now()
		for rows.Next() {
			var kid, status string
			var since time.Time
			if err := rows.Scan(&kid, &status, &since); err != nil {
				return err
			}
			switch status {
			case "active":
				hasActive, activeKID, activeAge = true, kid, now.Sub(since)
			case "next":
				hasNext, nextKID, nextAge = true, kid, now.Sub(since)
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE signing_keys SET status = 'retired'
			WHERE status = 'retiring' AND retire_at IS NOT NULL AND retire_at < now()`)
		if err != nil {
			return err
		}
		retireSome = tag.RowsAffected() > 0
		return nil
	})
	if err != nil {
		return err
	}

	switch {
	case hasNext && nextAge >= PrePublish:
		promoted := false
		err = k.DB.Bypass(ctx, "signing-key-promote", func(tx pgx.Tx) error {
			// Promote only a key that is still next. Between the read above
			// and here an operator may have revoked it (Replace), and a
			// revoked key must not come back as the active one.
			tag, err := tx.Exec(ctx, `UPDATE signing_keys SET status = 'active', activated_at = now()
				WHERE kid = $1 AND status = 'next'`, nextKID)
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			promoted = true
			_, err = tx.Exec(ctx, `UPDATE signing_keys SET status = 'retiring', retire_at = now() + interval '30 days'
				WHERE status = 'active' AND kid <> $1`, nextKID)
			return err
		})
		if err != nil {
			return err
		}
		if k.Log != nil && promoted {
			k.Log.Info("signing key promoted", "kid", nextKID, "replaced", activeKID)
		}
	case hasActive && !hasNext && activeAge >= maxAge:
		if err := k.Rotate(ctx, false); err != nil {
			return err
		}
		if k.Log != nil {
			k.Log.Info("signing key published for the next rotation", "replacing", activeKID)
		}
	case !retireSome:
		return nil
	}
	k.invalidate() // whatever changed, the cached set is stale
	return nil
}
