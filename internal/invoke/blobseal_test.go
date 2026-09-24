package invoke

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/supermcpco/supermcp/internal/secrets"
)

func TestSealedBlobStoreKeepsNothingInTheClear(t *testing.T) {
	ctx := context.Background()
	kek, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "test")
	if err != nil {
		t.Fatal(err)
	}
	inner := NewMemoryBlobStore(BlobOptions{BaseURL: "http://gw.test"})
	s := &SealedBlobStore{Inner: inner, Sealer: secrets.New(kek, secrets.NewMemoryKeyStore())}

	owner := BlobOwner{OrgID: "org-1", PrincipalID: "user-1"}
	secret := []byte("ACCOUNT 4242 BALANCE 1,000,000")
	ref, err := s.Put(ctx, Blob{Owner: owner, MediaType: "text/plain", Name: "statement.txt", Data: secret})
	if err != nil {
		t.Fatal(err)
	}

	// The inner store holds ciphertext.
	raw, ok, err := inner.Get(ctx, ref.ID, owner)
	if err != nil || !ok {
		t.Fatalf("inner get: ok=%v err=%v", ok, err)
	}
	if bytes.Contains(raw.Data, secret) || bytes.Contains(raw.Data, []byte("4242")) {
		t.Fatal("the inner store holds the result in the clear")
	}

	// The owner reads it back.
	got, ok, err := s.Get(ctx, ref.ID, owner)
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got.Data, secret) || got.MediaType != "text/plain" || got.Name != "statement.txt" {
		t.Fatalf("read back %q %s %s", got.Data, got.MediaType, got.Name)
	}

	// Somebody else gets nothing, as before, and the inner store's owner
	// check is what says so rather than a failed decryption.
	if _, ok, err := s.Get(ctx, ref.ID, BlobOwner{OrgID: "org-1", PrincipalID: "user-2"}); ok || err != nil {
		t.Fatalf("another principal read the blob: ok=%v err=%v", ok, err)
	}

	// A ciphertext handed to the wrong owner does not open: the binding is
	// in the ciphertext, not only in the store's query.
	other := BlobOwner{OrgID: "org-1", PrincipalID: "user-2"}
	if _, err := inner.Put(ctx, Blob{Owner: other, Data: raw.Data}); err != nil {
		t.Fatal(err)
	}
	moved, _ := inner.Put(ctx, Blob{Owner: other, Data: raw.Data})
	if _, _, err := s.Get(ctx, moved.ID, other); err == nil || !strings.Contains(err.Error(), "open blob") {
		t.Fatalf("a ciphertext moved to another principal opened: %v", err)
	}
}
