// Package secrets implements envelope encryption for everything sensitive
// the gateway stores.
//
//	KEK (local file/env, or a cloud KMS)  wraps  DEK per org + one instance DEK
//	DEK                                    seals  rows with AES-256-GCM
//
// Ciphertext layout (bytea, never base64 in the database):
//
//	byte 0       format version (0x01)
//	bytes 1..16  data key id (16 raw bytes of the DEK's UUID)
//	bytes 17..28 GCM nonce (12 bytes)
//	rest         AES-256-GCM ciphertext || 16-byte tag
//
// Additional authenticated data binds a ciphertext to its row so a value
// copied between rows or columns fails to open.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

const (
	formatVersion = 0x01
	keyIDLen      = 16
	nonceLen      = 12
	headerLen     = 1 + keyIDLen + nonceLen
	dekLen        = 32
)

// Errors.
var (
	ErrMalformed   = errors.New("ciphertext is malformed")
	ErrUnknownKey  = errors.New("ciphertext references an unknown data key")
	ErrKEKMaterial = errors.New("KEK material must be exactly 32 bytes (base64)")
)

// AAD identifies the row a value belongs to.
type AAD struct {
	Table, Column, RowID, OrgID string
}

func (a AAD) bytes() []byte {
	return []byte(a.Table + "\x00" + a.Column + "\x00" + a.RowID + "\x00" + a.OrgID)
}

// KEK wraps and unwraps data keys. Implementations: Local and AWSKMS.
type KEK interface {
	Ref() string
	Wrap(ctx context.Context, dek []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
}

// crossRef is implemented by a master key that can open data keys
// recorded under a reference other than its own: AWSKMS, for its
// multi-Region replicas in other regions.
type crossRef interface {
	forRef(ref string) (KEK, bool)
}

// openerFor returns the key that opens what was recorded under ref: k
// itself when the reference is its own, or what k says stands in for it.
func openerFor(k KEK, ref string) (KEK, bool) {
	if k == nil {
		return nil, false
	}
	if k.Ref() == ref {
		return k, true
	}
	if c, ok := k.(crossRef); ok {
		return c.forRef(ref)
	}
	return nil, false
}

// DataKey is a wrapped DEK as stored in data_keys.
type DataKey struct {
	ID      [keyIDLen]byte
	Scope   string // "org:<id>" or "instance"
	KEKRef  string
	Wrapped []byte
	Status  string // active | decrypt_only | retired
}

// KeyStore persists data keys.
type KeyStore interface {
	// Active returns the active key for a scope, or ok=false.
	Active(ctx context.Context, scope string) (*DataKey, bool, error)
	// Get returns a key by id regardless of status.
	Get(ctx context.Context, id [keyIDLen]byte) (*DataKey, bool, error)
	// Put stores a new key.
	Put(ctx context.Context, k *DataKey) error
}

// Sealer encrypts and decrypts with per-scope data keys.
type Sealer struct {
	kek   KEK
	older []KEK // decrypt-only master keys, in the order configured
	store KeyStore
	mu    sync.RWMutex
	deks  map[[keyIDLen]byte][]byte // unwrapped, process lifetime
}

// New builds a sealer. Keys given after the store may open a data key but
// never wrap one.
//
// Decrypt-only keys are what stop a master key rotation from being a
// maintenance window. While one runs, the database holds data keys under
// two master keys at once: a pod that has been rolled must still open the
// keys the outgoing master wrapped, and a pod that has not been rolled
// must open the ones the incoming master has already re-wrapped. Without
// the fallback both halves fail for as long as the rollout takes.
//
// Sealing stays on kek alone, deliberately. The outgoing key is usually
// outgoing because it is less trusted — a local key in an environment
// variable being replaced by KMS, or a key that may have leaked — and
// letting it wrap a freshly minted data key would put new secrets back
// under it and make the set of keys it protects grow again. With sealing
// pinned to one key that set can only shrink, so a rotation always
// terminates and dropping the old key from the configuration is the only
// step needed to finish it.
func New(kek KEK, store KeyStore, decryptOnly ...KEK) *Sealer {
	s := &Sealer{kek: kek, store: store, deks: map[[keyIDLen]byte][]byte{}}
	for _, k := range decryptOnly {
		if k != nil {
			s.older = append(s.older, k)
		}
	}
	return s
}

// ScopeOrg is the scope string for an organisation's key.
func ScopeOrg(orgID string) string { return "org:" + orgID }

// ScopeInstance is the scope for instance-wide secrets (signing keys, pepper).
const ScopeInstance = "instance"

// Seal encrypts plaintext under the scope's active DEK, creating one on
// first use.
func (s *Sealer) Seal(ctx context.Context, scope string, plaintext []byte, aad AAD) ([]byte, error) {
	dk, err := s.activeKey(ctx, scope)
	if err != nil {
		return nil, err
	}
	dek, err := s.unwrap(ctx, dk)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out := make([]byte, headerLen, headerLen+len(plaintext)+gcm.Overhead())
	out[0] = formatVersion
	copy(out[1:], dk.ID[:])
	nonce := out[1+keyIDLen : headerLen]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(out, nonce, plaintext, aad.bytes()), nil
}

// Open decrypts a value sealed by Seal. The AAD must match exactly.
func (s *Sealer) Open(ctx context.Context, ciphertext []byte, aad AAD) ([]byte, error) {
	if len(ciphertext) < headerLen+16 || ciphertext[0] != formatVersion {
		return nil, ErrMalformed
	}
	var id [keyIDLen]byte
	copy(id[:], ciphertext[1:1+keyIDLen])
	dk, ok, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrUnknownKey
	}
	dek, err := s.unwrap(ctx, dk)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[1+keyIDLen : headerLen]
	pt, err := gcm.Open(nil, nonce, ciphertext[headerLen:], aad.bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed", ErrMalformed)
	}
	return pt, nil
}

// KeyID returns the data key id a ciphertext references (for rotation
// jobs selecting rows by key).
func KeyID(ciphertext []byte) ([keyIDLen]byte, error) {
	var id [keyIDLen]byte
	if len(ciphertext) < headerLen || ciphertext[0] != formatVersion {
		return id, ErrMalformed
	}
	copy(id[:], ciphertext[1:1+keyIDLen])
	return id, nil
}

func (s *Sealer) activeKey(ctx context.Context, scope string) (*DataKey, error) {
	dk, ok, err := s.store.Active(ctx, scope)
	if err != nil {
		return nil, err
	}
	if ok {
		return dk, nil
	}
	// First use of this scope: mint a DEK, wrap it, store it.
	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	wrapped, err := s.kek.Wrap(ctx, dek)
	if err != nil {
		return nil, fmt.Errorf("wrap data key: %w", err)
	}
	nk := &DataKey{Scope: scope, KEKRef: s.kek.Ref(), Wrapped: wrapped, Status: "active"}
	if _, err := rand.Read(nk.ID[:]); err != nil {
		return nil, err
	}
	if err := s.store.Put(ctx, nk); err != nil {
		return nil, err
	}
	// Another replica may have won the race; re-read the active key.
	dk, ok, err = s.store.Active(ctx, scope)
	if err != nil || !ok {
		return nil, fmt.Errorf("data key for %s not found after create: %w", scope, err)
	}
	s.mu.Lock()
	if dk.ID == nk.ID {
		s.deks[nk.ID] = dek
	}
	s.mu.Unlock()
	return dk, nil
}

func (s *Sealer) unwrap(ctx context.Context, dk *DataKey) ([]byte, error) {
	s.mu.RLock()
	dek, ok := s.deks[dk.ID]
	s.mu.RUnlock()
	if ok {
		return dek, nil
	}
	kek, err := s.kekFor(dk)
	if err != nil {
		return nil, err
	}
	dek, err = kek.Unwrap(ctx, dk.Wrapped)
	if err != nil {
		return nil, fmt.Errorf("unwrap data key: %w", err)
	}
	if len(dek) != dekLen {
		return nil, errors.New("unwrapped data key has wrong length")
	}
	s.mu.Lock()
	s.deks[dk.ID] = dek
	s.mu.Unlock()
	return dek, nil
}

// kekFor picks the master key by the reference the data key records, not
// by the key this process seals with. Choosing by reference is what makes
// a wrong key a clean failure: a data key whose reference nothing here
// holds is refused outright rather than fed to every key in turn, so a
// blob substituted in data_keys.wrapped gets exactly one decryption
// attempt, under the key its own row names.
//
// A reference no key here spells exactly may still be one of them in
// another region (an AWS multi-Region key after a restore elsewhere); the
// key that says so is then the one attempt.
//
// The order is fixed, the active key and then each decrypt-only key as
// configured, and every exact match is tried before any cross-region
// one. An alias of one name can stand for unrelated keys in two regions,
// and the key recorded under the exact reference is the one that wrapped
// the data key.
func (s *Sealer) kekFor(dk *DataKey) (KEK, error) {
	if dk.KEKRef == s.kek.Ref() {
		return s.kek, nil
	}
	for _, k := range s.older {
		if k.Ref() == dk.KEKRef {
			return k, nil
		}
	}
	if k, ok := openerFor(s.kek, dk.KEKRef); ok {
		return k, nil
	}
	for _, o := range s.older {
		if k, ok := openerFor(o, dk.KEKRef); ok {
			return k, nil
		}
	}
	return nil, fmt.Errorf("data key %x is wrapped by KEK %q, which this process does not hold (it has %q)", dk.ID[:4], dk.KEKRef, s.kek.Ref())
}

// Forget drops unwrapped keys from memory (SIGHUP handler).
func (s *Sealer) Forget() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.deks {
		for i := range v {
			v[i] = 0
		}
		delete(s.deks, k)
	}
}

// ---------------------------------------------------------------------------
// Local KEK

// Local wraps DEKs with a 32-byte key held by the process (env or file).
// Wrapping uses AES-256-GCM with a random nonce: nonce || ct || tag.
type Local struct {
	key []byte
	ref string
}

// keyFileForbidden is the permission bits a key file may not carry:
// anything for other users, and group write or execute.
const keyFileForbidden os.FileMode = 0o037

// LocalFromEnv reads ENCRYPTION_KEK (base64, 32 bytes) or ENCRYPTION_KEK_FILE.
func LocalFromEnv(get func(string) string) (*Local, error) {
	if p := get("ENCRYPTION_KEK_FILE"); p != "" {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		// Group read is allowed and nothing else is. Kubernetes gives a
		// Secret volume's files to the pod's fsGroup and adds group read
		// whatever defaultMode says, so a key mounted into a non-root pod
		// is always 0440; refusing that would make the file form
		// unusable on the platform most installations run on. What stays
		// refused is the mistake the check exists for: a key any local
		// user can read, or one a group can overwrite.
		if st.Mode().Perm()&keyFileForbidden != 0 {
			return nil, fmt.Errorf("%s must not be world-readable or group-writable (mode %o); chmod 0400 or 0440", p, st.Mode().Perm())
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		return NewLocal(strings.TrimSpace(string(b)), "file:"+p)
	}
	if v := get("ENCRYPTION_KEK"); v != "" {
		return NewLocal(v, "env:ENCRYPTION_KEK")
	}
	return nil, errors.New("no KEK configured: set ENCRYPTION_KEK (openssl rand -base64 32) or ENCRYPTION_KEK_FILE")
}

// NewLocal decodes a base64 32-byte key. Any other length is refused
// outright rather than padded or truncated.
func NewLocal(b64, ref string) (*Local, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(b64))
	}
	if err != nil || len(key) != 32 {
		return nil, ErrKEKMaterial
	}
	return &Local{key: key, ref: ref}, nil
}

func (l *Local) Ref() string { return "local:" + l.ref }

func (l *Local) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	block, err := aes.NewCipher(l.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, dek, []byte("supermcp-dek")), nil
}

func (l *Local) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(l.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < gcm.NonceSize()+16 {
		return nil, ErrMalformed
	}
	return gcm.Open(nil, wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():], []byte("supermcp-dek"))
}

// ---------------------------------------------------------------------------
// In-memory key store (tests, and the bootstrap before the DB store exists)

// MemoryKeyStore keeps data keys in memory.
type MemoryKeyStore struct {
	mu   sync.Mutex
	keys map[[keyIDLen]byte]*DataKey
}

func NewMemoryKeyStore() *MemoryKeyStore { return &MemoryKeyStore{keys: map[[keyIDLen]byte]*DataKey{}} }

func (m *MemoryKeyStore) Active(_ context.Context, scope string) (*DataKey, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.keys {
		if k.Scope == scope && k.Status == "active" {
			cp := *k
			return &cp, true, nil
		}
	}
	return nil, false, nil
}

func (m *MemoryKeyStore) Get(_ context.Context, id [keyIDLen]byte) (*DataKey, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[id]
	if !ok {
		return nil, false, nil
	}
	cp := *k
	return &cp, true, nil
}

func (m *MemoryKeyStore) Put(_ context.Context, k *DataKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.keys {
		if existing.Scope == k.Scope && existing.Status == "active" {
			return nil // keep the first active key; caller re-reads
		}
	}
	cp := *k
	m.keys[k.ID] = &cp
	return nil
}
