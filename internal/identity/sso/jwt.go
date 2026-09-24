package sso

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ID tokens are verified here rather than trusted because they arrived
// over TLS. A provider's signature is what ties the claims to the issuer,
// and the check costs one cached key fetch.

// jwksTTL bounds how long a provider's keys are cached. A rotation is
// picked up by the refetch a miss triggers, so the window only matters for
// a key that is withdrawn rather than added.
const jwksTTL = 10 * time.Minute

type jwksCache struct {
	http Doer
	mu   sync.Mutex
	sets map[string]*jwkSet
}

type jwkSet struct {
	fetched time.Time
	keys    map[string]crypto.PublicKey
}

func newJWKSCache(h Doer) *jwksCache { return &jwksCache{http: h, sets: map[string]*jwkSet{}} }

// verify checks an ID token's signature against the provider's published
// keys and returns its claims.
func (c *jwksCache) verify(ctx context.Context, p *Provider, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: the id token is malformed", ErrProviderFailed)
	}
	head, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: the id token header is malformed", ErrProviderFailed)
	}
	var hdr struct{ Alg, Kid, Typ string }
	if err := json.Unmarshal(head, &hdr); err != nil {
		return nil, fmt.Errorf("%w: the id token header is malformed", ErrProviderFailed)
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: the id token payload is malformed", ErrProviderFailed)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: the id token payload is malformed", ErrProviderFailed)
	}
	if p.JWKSURI == "" {
		return nil, fmt.Errorf("%w: this provider publishes no signing keys, so its id token cannot be verified", ErrProviderFailed)
	}
	sig, err := decodeSegment(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: the id token signature is malformed", ErrProviderFailed)
	}
	key, err := c.key(ctx, p.JWKSURI, hdr.Kid)
	if err != nil {
		return nil, err
	}
	signed := []byte(parts[0] + "." + parts[1])
	if err := verifySignature(hdr.Alg, key, signed, sig); err != nil {
		return nil, err
	}
	return claims, nil
}

func (c *jwksCache) key(ctx context.Context, uri, kid string) (crypto.PublicKey, error) {
	if k, ok := c.lookup(uri, kid, false); ok {
		return k, nil
	}
	// A key we do not know may be a rotation: refetch once, then give up.
	if err := c.fetch(ctx, uri); err != nil {
		return nil, err
	}
	if k, ok := c.lookup(uri, kid, true); ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: the id token was signed with a key the provider does not publish", ErrProviderFailed)
}

func (c *jwksCache) lookup(uri, kid string, afterFetch bool) (crypto.PublicKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	set, ok := c.sets[uri]
	if !ok || (!afterFetch && time.Since(set.fetched) > jwksTTL) {
		return nil, false
	}
	if kid == "" && len(set.keys) == 1 {
		for _, k := range set.keys {
			return k, true
		}
	}
	k, ok := set.keys[kid]
	return k, ok
}

func (c *jwksCache) fetch(ctx context.Context, uri string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: could not fetch the provider's signing keys", ErrProviderFailed)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%w: the provider's key endpoint answered %s", ErrProviderFailed, resp.Status)
	}
	var doc struct {
		Keys []struct {
			Kty, Kid, Use, Alg, N, E, Crv, X, Y string
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("%w: the provider's key set is not valid JSON", ErrProviderFailed)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := publicKey(k.Kty, k.Crv, k.N, k.E, k.X, k.Y)
		if err != nil || pub == nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w: the provider published no usable signing keys", ErrProviderFailed)
	}
	c.mu.Lock()
	c.sets[uri] = &jwkSet{fetched: time.Now(), keys: keys}
	c.mu.Unlock()
	return nil
}

func publicKey(kty, crv, n, e, x, y string) (crypto.PublicKey, error) {
	switch kty {
	case "RSA":
		nb, err := decodeSegment(n)
		if err != nil {
			return nil, err
		}
		eb, err := decodeSegment(e)
		if err != nil {
			return nil, err
		}
		var exp uint64
		padded := make([]byte, 8)
		copy(padded[8-len(eb):], eb)
		exp = binary.BigEndian.Uint64(padded)
		if exp == 0 || exp > 1<<31 {
			return nil, errors.New("implausible RSA exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(exp)}, nil //nolint:gosec // bounded above
	case "EC":
		xb, err := decodeSegment(x)
		if err != nil {
			return nil, err
		}
		yb, err := decodeSegment(y)
		if err != nil {
			return nil, err
		}
		curve, err := curveByName(crv)
		if err != nil {
			return nil, err
		}
		// An uncompressed point is 0x04 followed by the two coordinates.
		size := (curve.Params().BitSize + 7) / 8
		buf := make([]byte, 1+2*size)
		buf[0] = 4
		copy(buf[1+size-len(xb):1+size], xb)
		copy(buf[1+2*size-len(yb):], yb)
		return ecdsa.ParseUncompressedPublicKey(curve, buf)
	}
	return nil, nil
}

func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) error {
	bad := fmt.Errorf("%w: the id token signature does not verify", ErrProviderFailed)
	switch alg {
	case "RS256", "RS384", "RS512":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return bad
		}
		h, sum := digest(alg, signed)
		if err := rsa.VerifyPKCS1v15(pub, h, sum, sig); err != nil {
			return bad
		}
		return nil
	case "PS256", "PS384", "PS512":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return bad
		}
		h, sum := digest(alg, signed)
		if err := rsa.VerifyPSS(pub, h, sum, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
			return bad
		}
		return nil
	case "ES256", "ES384", "ES512":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return bad
		}
		_, sum := digest(alg, signed)
		half := len(sig) / 2
		if len(sig) == 0 || len(sig)%2 != 0 {
			return bad
		}
		r := new(big.Int).SetBytes(sig[:half])
		s := new(big.Int).SetBytes(sig[half:])
		if !ecdsa.Verify(pub, sum, r, s) {
			return bad
		}
		return nil
	}
	// "none" and anything unknown are refused: an unsigned token proves
	// nothing, whoever sent it.
	return fmt.Errorf("%w: the id token uses the unsupported signature algorithm %q", ErrProviderFailed, alg)
}

func digest(alg string, b []byte) (crypto.Hash, []byte) {
	switch alg[2:] {
	case "384":
		sum := sha512.Sum384(b)
		return crypto.SHA384, sum[:]
	case "512":
		sum := sha512.Sum512(b)
		return crypto.SHA512, sum[:]
	default:
		sum := sha256.Sum256(b)
		return crypto.SHA256, sum[:]
	}
}

// checkIDToken validates the claims that say who issued the token, who it
// is for, and that it belongs to this sign-in.
func checkIDToken(claims map[string]any, p *Provider, nonce string, now time.Time) error {
	const skew = 2 * time.Minute
	iss := strings.TrimSuffix(claimString(claims, "iss"), "/")
	if p.Issuer != "" && iss != strings.TrimSuffix(p.Issuer, "/") {
		return fmt.Errorf("%w: the id token was issued by %s", ErrProviderFailed, iss)
	}
	if !audienceContains(claims["aud"], p.ClientID) {
		return fmt.Errorf("%w: the id token is addressed to another application", ErrProviderFailed)
	}
	exp, ok := claimTime(claims, "exp")
	if !ok || now.After(exp.Add(skew)) {
		return fmt.Errorf("%w: the id token has expired", ErrProviderFailed)
	}
	if iat, ok := claimTime(claims, "iat"); ok && iat.After(now.Add(skew)) {
		return fmt.Errorf("%w: the id token is dated in the future", ErrProviderFailed)
	}
	// The nonce ties the token to the request we started: without it, a
	// token obtained elsewhere could be replayed into this sign-in.
	if got := claimString(claims, "nonce"); got != nonce {
		return fmt.Errorf("%w: the id token belongs to a different sign-in", ErrProviderFailed)
	}
	return nil
}

func audienceContains(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

func claimTime(m map[string]any, key string) (time.Time, bool) {
	switch v := m[key].(type) {
	case float64:
		return time.Unix(int64(v), 0), true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(n, 0), true
	}
	return time.Time{}, false
}

func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func curveByName(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("unsupported curve %q", crv)
}
