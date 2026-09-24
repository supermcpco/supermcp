package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
)

func newSealer(t *testing.T) *Sealer {
	t.Helper()
	kek, err := NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "test")
	if err != nil {
		t.Fatal(err)
	}
	return New(kek, NewMemoryKeyStore())
}

func TestSealOpenRoundTrip(t *testing.T) {
	s := newSealer(t)
	ctx := context.Background()
	aad := AAD{Table: "connectors", Column: "auth", RowID: "c1", OrgID: "o1"}
	ct, err := s.Seal(ctx, ScopeOrg("o1"), []byte(`{"token":"x"}`), aad)
	if err != nil {
		t.Fatal(err)
	}
	if ct[0] != formatVersion || len(ct) != headerLen+len(`{"token":"x"}`)+16 {
		t.Fatalf("unexpected layout len=%d", len(ct))
	}
	pt, err := s.Open(ctx, ct, aad)
	if err != nil || string(pt) != `{"token":"x"}` {
		t.Fatalf("open: %q %v", pt, err)
	}
	// Same scope reuses the DEK; different scope gets a different key id.
	ct2, _ := s.Seal(ctx, ScopeOrg("o1"), []byte("y"), aad)
	ct3, _ := s.Seal(ctx, ScopeOrg("o2"), []byte("y"), AAD{OrgID: "o2"})
	id1, _ := KeyID(ct)
	id2, _ := KeyID(ct2)
	id3, _ := KeyID(ct3)
	if id1 != id2 || id1 == id3 {
		t.Fatal("DEK scoping wrong")
	}
	// Nonces differ per seal.
	if bytes.Equal(ct[1+keyIDLen:headerLen], ct2[1+keyIDLen:headerLen]) {
		t.Fatal("nonce reused")
	}
}

func TestAADBindsRow(t *testing.T) {
	s := newSealer(t)
	ctx := context.Background()
	ct, _ := s.Seal(ctx, ScopeOrg("o1"), []byte("secret"), AAD{Table: "t", Column: "c", RowID: "r1", OrgID: "o1"})
	for _, bad := range []AAD{
		{Table: "t", Column: "c", RowID: "r2", OrgID: "o1"},
		{Table: "t", Column: "d", RowID: "r1", OrgID: "o1"},
		{Table: "t", Column: "c", RowID: "r1", OrgID: "o2"},
		{},
	} {
		if _, err := s.Open(ctx, ct, bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("aad %+v: expected failure, got %v", bad, err)
		}
	}
}

func TestTamperAndUnknownKey(t *testing.T) {
	s := newSealer(t)
	ctx := context.Background()
	aad := AAD{OrgID: "o1"}
	ct, _ := s.Seal(ctx, ScopeOrg("o1"), []byte("secret"), aad)
	flipped := append([]byte{}, ct...)
	flipped[len(flipped)-1] ^= 1
	if _, err := s.Open(ctx, flipped, aad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("tamper: %v", err)
	}
	other := append([]byte{}, ct...)
	other[5] ^= 0xff
	if _, err := s.Open(ctx, other, aad); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
	if _, err := s.Open(ctx, []byte{0x02, 0, 0}, aad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("bad version: %v", err)
	}
	// A different KEK cannot unwrap the DEK.
	other2, _ := NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), "other")
	s2 := New(other2, s.store)
	if _, err := s2.Open(ctx, ct, aad); err == nil {
		t.Fatal("expected KEK mismatch")
	}
}

func TestLocalKEKMaterial(t *testing.T) {
	for _, bad := range []string{"", "short", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 20)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 33)), "not base64!!"} {
		if _, err := NewLocal(bad, "x"); !errors.Is(err, ErrKEKMaterial) {
			t.Errorf("%q: expected ErrKEKMaterial, got %v", bad, err)
		}
	}
	if _, err := NewLocal(base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "x"); err != nil {
		t.Errorf("raw base64 should be accepted: %v", err)
	}
	if _, err := LocalFromEnv(func(string) string { return "" }); err == nil {
		t.Error("expected error without KEK")
	}
}

func TestForgetThenReopen(t *testing.T) {
	s := newSealer(t)
	ctx := context.Background()
	aad := AAD{OrgID: "o1"}
	ct, _ := s.Seal(ctx, ScopeOrg("o1"), []byte("v"), aad)
	s.Forget()
	if pt, err := s.Open(ctx, ct, aad); err != nil || string(pt) != "v" {
		t.Fatalf("reopen after forget: %q %v", pt, err)
	}
}
