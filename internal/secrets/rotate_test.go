package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"testing"
)

var errStoreDown = errors.New("store is unavailable")

// rotStore is MemoryKeyStore plus the rotation surface. Reaching into the
// map is deliberate: the test store must behave like the SQL one, where
// an update is a single atomic statement.
type rotStore struct {
	*MemoryKeyStore
	rewraps  int
	rewrapAt int // fail on this re-wrap, 1-based; 0 never fails
}

func newRotStore() *rotStore { return &rotStore{MemoryKeyStore: NewMemoryKeyStore()} }

func (s *rotStore) ListDataKeys(_ context.Context) ([]*DataKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*DataKey, 0, len(s.keys))
	for _, k := range s.keys {
		cp := *k
		out = append(out, &cp)
	}
	slices.SortFunc(out, func(a, b *DataKey) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	return out, nil
}

func (s *rotStore) ReWrapDataKey(_ context.Context, id [keyIDLen]byte, ref string, wrapped []byte) error {
	s.rewraps++
	if s.rewrapAt != 0 && s.rewraps == s.rewrapAt {
		return errStoreDown
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return fmt.Errorf("no data key %x", id[:4])
	}
	k.KEKRef, k.Wrapped = ref, bytes.Clone(wrapped)
	return nil
}

func (s *rotStore) SetDataKeyStatus(_ context.Context, id [keyIDLen]byte, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return fmt.Errorf("no data key %x", id[:4])
	}
	k.Status = status
	return nil
}

func (s *rotStore) statusOf(t *testing.T, id [keyIDLen]byte) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		t.Fatalf("no data key %x", id[:4])
	}
	return k.Status
}

func testKEK(t *testing.T, b byte, name string) *Local {
	t.Helper()
	k, err := NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)), name)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// brokenKEK encrypts happily and returns something else on the way back,
// which is what a key with encrypt-only permissions or a mismatched
// encryption context looks like from here.
type brokenKEK struct{}

func (brokenKEK) Ref() string { return "local:broken" }
func (brokenKEK) Wrap(context.Context, []byte) ([]byte, error) {
	return []byte("looks-like-a-blob"), nil
}
func (brokenKEK) Unwrap(context.Context, []byte) ([]byte, error) { return make([]byte, dekLen), nil }

// cancelAfter cancels the context once the wrapped KEK has been used n
// times, standing in for an operator interrupting a long run.
type cancelAfter struct {
	KEK
	n      int
	cancel context.CancelFunc
}

func (c *cancelAfter) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	out, err := c.KEK.Wrap(ctx, dek)
	if c.n--; c.n == 0 {
		c.cancel()
	}
	return out, err
}

func seedScopes(t *testing.T, s *Sealer, scopes ...string) map[string][]byte {
	t.Helper()
	ctx := context.Background()
	out := map[string][]byte{}
	for _, sc := range scopes {
		aad := AAD{Table: "t", Column: "c", RowID: sc, OrgID: sc}
		ct, err := s.Seal(ctx, sc, []byte("secret-"+sc), aad)
		if err != nil {
			t.Fatalf("seal %s: %v", sc, err)
		}
		out[sc] = ct
	}
	return out
}

func TestRotateKEKReWrapsEveryKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newRotStore()
	oldKEK, newKEK := testKEK(t, 1, "k1"), testKEK(t, 2, "k2")
	cts := seedScopes(t, New(oldKEK, store), ScopeOrg("o1"), ScopeOrg("o2"), ScopeInstance)

	rep, err := RotateKEK(ctx, KEKRotation{Store: store, To: newKEK, From: []KEK{oldKEK}})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rep.Examined != 3 || rep.ReWrapped != 3 || rep.Skipped != 0 {
		t.Fatalf("report = %+v", rep)
	}
	keys, _ := store.ListDataKeys(ctx)
	for _, k := range keys {
		if k.KEKRef != newKEK.Ref() {
			t.Errorf("key %x still records %q", k.ID[:4], k.KEKRef)
		}
	}
	// Ciphertext is untouched and opens under the new master key.
	fresh := New(newKEK, store)
	for scope, ct := range cts {
		pt, err := fresh.Open(ctx, ct, AAD{Table: "t", Column: "c", RowID: scope, OrgID: scope})
		if err != nil || string(pt) != "secret-"+scope {
			t.Errorf("open %s: %q %v", scope, pt, err)
		}
	}
	// A second run has nothing left to do.
	rep2, err := RotateKEK(ctx, KEKRotation{Store: store, To: newKEK, From: []KEK{oldKEK}})
	if err != nil || rep2.ReWrapped != 0 || rep2.Skipped != 3 {
		t.Fatalf("second run: %+v %v", rep2, err)
	}
}

func TestRotateKEKResumesAfterFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newRotStore()
	oldKEK, newKEK := testKEK(t, 1, "k1"), testKEK(t, 2, "k2")
	seedScopes(t, New(oldKEK, store), ScopeOrg("o1"), ScopeOrg("o2"), ScopeInstance)

	store.rewrapAt = 2
	rep, err := RotateKEK(ctx, KEKRotation{Store: store, To: newKEK, From: []KEK{oldKEK}})
	if !errors.Is(err, errStoreDown) {
		t.Fatalf("err = %v, want the store error", err)
	}
	if rep.ReWrapped != 1 {
		t.Fatalf("report = %+v, want one key moved before the failure", rep)
	}

	store.rewrapAt = 0
	rep2, err := RotateKEK(ctx, KEKRotation{Store: store, To: newKEK, From: []KEK{oldKEK}})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if rep2.Skipped != 1 || rep2.ReWrapped != 2 {
		t.Fatalf("resume report = %+v", rep2)
	}
	keys, _ := store.ListDataKeys(ctx)
	for _, k := range keys {
		if k.KEKRef != newKEK.Ref() {
			t.Errorf("key %x still records %q", k.ID[:4], k.KEKRef)
		}
	}
}

func TestRotateKEKStopsOnCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newRotStore()
	oldKEK := testKEK(t, 1, "k1")
	seedScopes(t, New(oldKEK, store), ScopeOrg("o1"), ScopeOrg("o2"), ScopeInstance)

	newKEK := &cancelAfter{KEK: testKEK(t, 2, "k2"), n: 1, cancel: cancel}
	rep, err := RotateKEK(ctx, KEKRotation{Store: store, To: newKEK, From: []KEK{oldKEK}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if rep.ReWrapped != 1 || rep.Examined != 1 {
		t.Fatalf("report = %+v, want progress up to the cancellation", rep)
	}
}

func TestRotateKEKRefusesUnknownWrapper(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newRotStore()
	oldKEK := testKEK(t, 1, "k1")
	seedScopes(t, New(oldKEK, store), ScopeOrg("o1"))

	rep, err := RotateKEK(ctx, KEKRotation{Store: store, To: testKEK(t, 2, "k2")})
	if err == nil {
		t.Fatal("expected a refusal when the current master key was not supplied")
	}
	if rep.ReWrapped != 0 {
		t.Fatalf("report = %+v", rep)
	}
}

func TestRotateKEKVerifiesBeforeOverwriting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newRotStore()
	oldKEK := testKEK(t, 1, "k1")
	cts := seedScopes(t, New(oldKEK, store), ScopeOrg("o1"))

	if _, err := RotateKEK(ctx, KEKRotation{Store: store, To: brokenKEK{}, From: []KEK{oldKEK}}); err == nil {
		t.Fatal("expected a KEK that cannot decrypt its own output to be caught")
	}
	keys, _ := store.ListDataKeys(ctx)
	for _, k := range keys {
		if k.KEKRef != oldKEK.Ref() {
			t.Fatalf("key %x was overwritten with an unusable wrapping", k.ID[:4])
		}
	}
	pt, err := New(oldKEK, store).Open(ctx, cts[ScopeOrg("o1")], AAD{Table: "t", Column: "c", RowID: ScopeOrg("o1"), OrgID: ScopeOrg("o1")})
	if err != nil || !bytes.Equal(pt, []byte("secret-"+ScopeOrg("o1"))) {
		t.Fatalf("data unreadable after a refused rotation: %q %v", pt, err)
	}
}

func TestRotateKEKValidates(t *testing.T) {
	t.Parallel()
	if _, err := RotateKEK(context.Background(), KEKRotation{}); err == nil {
		t.Fatal("expected an error without a store or target key")
	}
}

// ---------------------------------------------------------------------------
// Data key rotation

var testTarget = ReSealTarget{Table: "connector_credentials", Column: "value_enc", IDColumn: "connector_id"}

// memTable is a caller's table of sealed rows.
type memTable struct {
	rows    []SealedRow
	batches int
	failAt  int // fail on this batch write, 1-based; 0 never fails
	onBatch func()
}

func (m *memTable) SealedRows(_ context.Context, _ ReSealTarget, after string, limit int) ([]SealedRow, error) {
	out := make([]SealedRow, 0, limit)
	for _, r := range m.rows {
		if r.Cursor <= after {
			continue
		}
		cp := r
		cp.Value = bytes.Clone(r.Value)
		out = append(out, cp)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (m *memTable) WriteSealed(_ context.Context, _ ReSealTarget, rows []SealedRow) (int, error) {
	m.batches++
	if m.failAt != 0 && m.batches == m.failAt {
		return 0, errStoreDown
	}
	written := 0
	for _, r := range rows {
		i := slices.IndexFunc(m.rows, func(x SealedRow) bool { return x.Cursor == r.Cursor })
		if i < 0 {
			// A row that went away between being read and being written,
			// which the SQL store reports the same way.
			continue
		}
		m.rows[i].Value = bytes.Clone(r.Value)
		written++
	}
	if m.onBatch != nil {
		m.onBatch()
	}
	return written, nil
}

// KeyCensus counts the table's rows by the key each one names, as the SQL
// store does with a group-by over the key id in the ciphertext header.
func (m *memTable) KeyCensus(_ context.Context, _ ReSealTarget) (map[[keyIDLen]byte]int, error) {
	out := map[[keyIDLen]byte]int{}
	for _, r := range m.rows {
		if len(r.Value) == 0 {
			continue
		}
		id, err := KeyID(r.Value)
		if err != nil {
			return nil, fmt.Errorf("row %q: %w", r.Cursor, err)
		}
		out[id]++
	}
	return out, nil
}

func seedTable(t *testing.T, s *Sealer, scope string, n int) *memTable {
	t.Helper()
	ctx := context.Background()
	tbl := &memTable{rows: make([]SealedRow, 0, n)}
	for i := range n {
		cursor := fmt.Sprintf("row-%03d", i)
		aad := AAD{Table: testTarget.Table, Column: testTarget.Column, RowID: cursor, OrgID: "o1"}
		ct, err := s.Seal(ctx, scope, []byte("value-"+cursor), aad)
		if err != nil {
			t.Fatalf("seal %s: %v", cursor, err)
		}
		tbl.rows = append(tbl.rows, SealedRow{Cursor: cursor, AAD: aad, Value: ct})
	}
	return tbl
}

func (m *memTable) checkAll(t *testing.T, s *Sealer, key [keyIDLen]byte) {
	t.Helper()
	ctx := context.Background()
	for _, r := range m.rows {
		id, err := KeyID(r.Value)
		if err != nil {
			t.Fatalf("row %q: %v", r.Cursor, err)
		}
		if id != key {
			t.Errorf("row %q is on key %x, want %x", r.Cursor, id[:4], key[:4])
		}
		pt, err := s.Open(ctx, r.Value, r.AAD)
		if err != nil || string(pt) != "value-"+r.Cursor {
			t.Errorf("row %q: %q %v", r.Cursor, pt, err)
		}
	}
}

func TestRotateDataKeyReSealsInBatches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newRotStore()
	kek := testKEK(t, 1, "k1")
	sealer := New(kek, store)
	scope := ScopeOrg("o1")
	tbl := seedTable(t, sealer, scope, 25)

	rep, err := RotateDataKey(ctx, DataKeyRotation{
		Store: store, Sealer: sealer, Rows: tbl, Scope: scope,
		Targets: []ReSealTarget{testTarget}, Batch: 10,
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rep.OldKeyID == rep.NewKeyID {
		t.Fatal("the scope kept the same data key")
	}
	if rep.Scanned != 25 || rep.ReSealed != 25 {
		t.Fatalf("report = %+v", rep)
	}
	if tbl.batches != 3 {
		t.Fatalf("batches = %d, want 3 for 25 rows of 10", tbl.batches)
	}
	if got := store.statusOf(t, rep.OldKeyID); got != statusDecryptOnly {
		t.Errorf("old key status = %q, want %q", got, statusDecryptOnly)
	}
	if got := store.statusOf(t, rep.NewKeyID); got != "active" {
		t.Errorf("new key status = %q, want active", got)
	}
	tbl.checkAll(t, New(kek, store), rep.NewKeyID)
}

func TestRotateDataKeyResumesWithReSealOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newRotStore()
	kek := testKEK(t, 1, "k1")
	sealer := New(kek, store)
	scope := ScopeOrg("o1")
	tbl := seedTable(t, sealer, scope, 25)

	tbl.failAt = 2
	rep, err := RotateDataKey(ctx, DataKeyRotation{
		Store: store, Sealer: sealer, Rows: tbl, Scope: scope,
		Targets: []ReSealTarget{testTarget}, Batch: 10,
	})
	if !errors.Is(err, errStoreDown) {
		t.Fatalf("err = %v, want the store error", err)
	}
	if rep.ReSealed != 10 {
		t.Fatalf("report = %+v, want the first batch written", rep)
	}

	tbl.failAt = 0
	rep2, err := RotateDataKey(ctx, DataKeyRotation{
		Store: store, Sealer: sealer, Rows: tbl, Scope: scope,
		Targets: []ReSealTarget{testTarget}, Batch: 10, ReSealOnly: true,
	})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if rep2.NewKeyID != rep.NewKeyID {
		t.Fatal("the resume minted another data key")
	}
	if rep2.Scanned != 25 || rep2.ReSealed != 15 {
		t.Fatalf("resume report = %+v, want the remaining 15 rows", rep2)
	}
	keys, _ := store.ListDataKeys(ctx)
	if len(keys) != 2 {
		t.Fatalf("data keys = %d, want the old one and one replacement", len(keys))
	}
	tbl.checkAll(t, New(kek, store), rep.NewKeyID)
}

func TestRotateDataKeyStopsOnCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newRotStore()
	kek := testKEK(t, 1, "k1")
	sealer := New(kek, store)
	scope := ScopeOrg("o1")
	tbl := seedTable(t, sealer, scope, 25)
	tbl.onBatch = cancel

	rep, err := RotateDataKey(ctx, DataKeyRotation{
		Store: store, Sealer: sealer, Rows: tbl, Scope: scope,
		Targets: []ReSealTarget{testTarget}, Batch: 10,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if rep.ReSealed != 10 {
		t.Fatalf("report = %+v, want the first batch only", rep)
	}
	// Whatever was written is readable; the rest is still on the old key.
	fresh := New(kek, store)
	for _, r := range tbl.rows {
		if _, err := fresh.Open(ctx, r.Value, r.AAD); err != nil {
			t.Errorf("row %q unreadable mid-rotation: %v", r.Cursor, err)
		}
	}
}

func TestRotateDataKeyValidates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newRotStore()
	sealer := New(testKEK(t, 1, "k1"), store)
	if _, err := RotateDataKey(ctx, DataKeyRotation{Sealer: sealer, Rows: &memTable{}, Scope: "x"}); err == nil {
		t.Error("expected an error without a store")
	}
	if _, err := RotateDataKey(ctx, DataKeyRotation{Store: store, Sealer: sealer, Rows: &memTable{}}); err == nil {
		t.Error("expected an error without a scope")
	}
	// A scope that has never been used has nothing to rotate.
	if _, err := RotateDataKey(ctx, DataKeyRotation{Store: store, Sealer: sealer, Rows: &memTable{}, Scope: ScopeOrg("nobody")}); err == nil {
		t.Error("expected an error for a scope with no active key")
	}
}

func TestReSealTargetString(t *testing.T) {
	t.Parallel()
	if got := testTarget.String(); got != "connector_credentials.value_enc" {
		t.Errorf("String() = %q", got)
	}
}
