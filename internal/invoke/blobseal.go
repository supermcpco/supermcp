package invoke

import (
	"context"
	"fmt"

	"github.com/supermcpco/supermcp/internal/secrets"
)

// SealedBlobStore encrypts what it stores under the workspace's data key
// and decrypts what it reads. A blob is a tool's result, and a tool's
// result is whatever the upstream system answered: a customer record, a
// statement, a signed document. Everything else the gateway keeps at
// rest for a workspace is sealed with that workspace's key, and a result
// that sits in Postgres or Redis for a quarter of an hour in the clear
// would be the one exception, so there is none.
//
// The ciphertext is bound to the workspace and the principal it was
// stored for. Moving it between rows, or between stores, does not open
// it for anybody else.
type SealedBlobStore struct {
	Inner  BlobStore
	Sealer *secrets.Sealer
}

func blobAAD(o BlobOwner) secrets.AAD {
	return secrets.AAD{Table: "tool_blobs", Column: "data", RowID: o.PrincipalID, OrgID: o.OrgID}
}

// Put seals the data, then stores it.
func (s *SealedBlobStore) Put(ctx context.Context, b Blob) (BlobRef, error) {
	if b.Owner.Zero() {
		return BlobRef{}, fmt.Errorf("blob needs an owner")
	}
	ct, err := s.Sealer.Seal(ctx, secrets.ScopeOrg(b.Owner.OrgID), b.Data, blobAAD(b.Owner))
	if err != nil {
		return BlobRef{}, fmt.Errorf("seal blob: %w", err)
	}
	b.Data = ct
	return s.Inner.Put(ctx, b)
}

// Get reads the blob and opens it for its owner.
func (s *SealedBlobStore) Get(ctx context.Context, id string, owner BlobOwner) (Blob, bool, error) {
	b, ok, err := s.Inner.Get(ctx, id, owner)
	if !ok || err != nil {
		return b, ok, err
	}
	pt, err := s.Sealer.Open(ctx, b.Data, blobAAD(owner))
	if err != nil {
		return Blob{}, false, fmt.Errorf("open blob: %w", err)
	}
	b.Data = pt
	return b, true, nil
}
