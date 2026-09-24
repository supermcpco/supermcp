package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// errKMSDown stands in for any service-side failure.
var errKMSDown = errors.New("kms is unavailable")

type kmsBlob struct {
	plaintext []byte
	keyID     string
	encCtx    map[string]string
}

// fakeKMS behaves like KMS for the properties this package depends on: a
// blob is opaque, it remembers the key and the encryption context it was
// made with, and decrypting with either one different is refused.
type fakeKMS struct {
	mu      sync.Mutex
	blobs   map[string]kmsBlob
	n       int
	encErr  error
	decErr  error
	encCall int
	decCall int
}

func newFakeKMS() *fakeKMS { return &fakeKMS{blobs: map[string]kmsBlob{}} }

func (f *fakeKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.encCall++
	if f.encErr != nil {
		return nil, f.encErr
	}
	f.n++
	blob := "blob-" + strconv.Itoa(f.n)
	f.blobs[blob] = kmsBlob{
		plaintext: bytes.Clone(in.Plaintext),
		keyID:     *in.KeyId,
		encCtx:    maps.Clone(in.EncryptionContext),
	}
	return &kms.EncryptOutput{CiphertextBlob: []byte(blob), KeyId: in.KeyId}, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decCall++
	if f.decErr != nil {
		return nil, f.decErr
	}
	rec, ok := f.blobs[string(in.CiphertextBlob)]
	if !ok {
		return nil, errors.New("InvalidCiphertextException: unknown blob")
	}
	if in.KeyId != nil && *in.KeyId != rec.keyID {
		return nil, fmt.Errorf("IncorrectKeyException: blob was made with %s", rec.keyID)
	}
	if !maps.Equal(in.EncryptionContext, rec.encCtx) {
		return nil, errors.New("InvalidCiphertextException: encryption context mismatch")
	}
	return &kms.DecryptOutput{Plaintext: bytes.Clone(rec.plaintext), KeyId: &rec.keyID}, nil
}

func testKMS(t *testing.T, c *fakeKMS, cfg AWSKMSConfig) *AWSKMS {
	t.Helper()
	cfg.Client = c
	if cfg.KeyID == "" {
		cfg.KeyID = "alias/supermcp"
	}
	if cfg.Region == "" {
		cfg.Region = "eu-west-1"
	}
	k, err := NewAWSKMSFromConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("build kek: %v", err)
	}
	return k
}

func TestAWSKMSRoundTrip(t *testing.T) {
	t.Parallel()
	c := newFakeKMS()
	k := testKMS(t, c, AWSKMSConfig{Deployment: "prod-eu"})
	ctx := context.Background()

	dek := bytes.Repeat([]byte{3}, dekLen)
	wrapped, err := k.Wrap(ctx, dek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped blob contains the plaintext data key")
	}
	got, err := k.Unwrap(ctx, wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("round trip mismatch: %x", got)
	}

	// The deployment binding is what separates two installations sharing
	// one key, so assert it actually reaches the service.
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rec := range c.blobs {
		want := map[string]string{"app": "supermcp", "purpose": "data-key-wrap", "deployment": "prod-eu"}
		if !maps.Equal(rec.encCtx, want) {
			t.Fatalf("encryption context = %v, want %v", rec.encCtx, want)
		}
	}
}

func TestAWSKMSWrapsThroughSealer(t *testing.T) {
	t.Parallel()
	c := newFakeKMS()
	k := testKMS(t, c, AWSKMSConfig{Deployment: "prod-eu"})
	s := New(k, NewMemoryKeyStore())
	ctx := context.Background()
	aad := AAD{Table: "connector_credentials", Column: "value_enc", RowID: "c1/token", OrgID: "o1"}
	ct, err := s.Seal(ctx, ScopeOrg("o1"), []byte("hunter2"), aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	s.Forget()
	pt, err := s.Open(ctx, ct, aad)
	if err != nil || string(pt) != "hunter2" {
		t.Fatalf("open: %q %v", pt, err)
	}
}

func TestAWSKMSEncryptionContextIsEnforced(t *testing.T) {
	t.Parallel()
	c := newFakeKMS()
	ctx := context.Background()
	prod := testKMS(t, c, AWSKMSConfig{Deployment: "prod-eu"})
	staging := testKMS(t, c, AWSKMSConfig{Deployment: "staging-eu"})

	wrapped, err := prod.Wrap(ctx, bytes.Repeat([]byte{4}, dekLen))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if _, err := staging.Unwrap(ctx, wrapped); err == nil {
		t.Fatal("a blob lifted from production opened in staging")
	}
	// The same key with the same deployment still opens it, so the refusal
	// above is the context and not an accident of the fake.
	again := testKMS(t, c, AWSKMSConfig{Deployment: "prod-eu"})
	if _, err := again.Unwrap(ctx, wrapped); err != nil {
		t.Fatalf("same deployment should unwrap: %v", err)
	}
}

func TestAWSKMSPinsTheKeyOnDecrypt(t *testing.T) {
	t.Parallel()
	c := newFakeKMS()
	ctx := context.Background()
	mine := testKMS(t, c, AWSKMSConfig{KeyID: "alias/supermcp", Deployment: "prod"})
	theirs := testKMS(t, c, AWSKMSConfig{KeyID: "alias/attacker", Deployment: "prod"})

	planted, err := theirs.Wrap(ctx, bytes.Repeat([]byte{9}, dekLen))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if _, err := mine.Unwrap(ctx, planted); err == nil {
		t.Fatal("a blob made under another key was adopted")
	}
}

func TestAWSKMSServiceErrorsSurface(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	c := newFakeKMS()
	c.encErr = errKMSDown
	k := testKMS(t, c, AWSKMSConfig{})
	out, err := k.Wrap(ctx, bytes.Repeat([]byte{1}, dekLen))
	if !errors.Is(err, errKMSDown) {
		t.Fatalf("wrap error = %v, want the service error", err)
	}
	if out != nil {
		t.Fatal("a failed wrap returned bytes")
	}

	c2 := newFakeKMS()
	k2 := testKMS(t, c2, AWSKMSConfig{})
	wrapped, err := k2.Wrap(ctx, bytes.Repeat([]byte{1}, dekLen))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	c2.decErr = errKMSDown
	if _, err := k2.Unwrap(ctx, wrapped); !errors.Is(err, errKMSDown) {
		t.Fatalf("unwrap error = %v, want the service error", err)
	}

	// A sealer must not cache anything from a failed unwrap.
	c3 := newFakeKMS()
	c3.encErr = errKMSDown
	s := New(testKMS(t, c3, AWSKMSConfig{}), NewMemoryKeyStore())
	if _, err := s.Seal(ctx, ScopeInstance, []byte("x"), AAD{}); !errors.Is(err, errKMSDown) {
		t.Fatalf("seal error = %v, want the service error", err)
	}
	c3.encErr = nil
	if _, err := s.Seal(ctx, ScopeInstance, []byte("x"), AAD{}); err != nil {
		t.Fatalf("seal after recovery: %v", err)
	}
}

func TestAWSKMSWrapRejectsBadInput(t *testing.T) {
	t.Parallel()
	c := newFakeKMS()
	k := testKMS(t, c, AWSKMSConfig{})
	ctx := context.Background()
	if _, err := k.Wrap(ctx, nil); err == nil {
		t.Error("expected an error for an empty data key")
	}
	if _, err := k.Wrap(ctx, make([]byte, kmsPlaintextLimit+1)); err == nil {
		t.Error("expected an error over the plaintext limit")
	}
	if _, err := k.Unwrap(ctx, nil); !errors.Is(err, ErrMalformed) {
		t.Errorf("empty blob = %v, want ErrMalformed", err)
	}
	if c.encCall != 0 || c.decCall != 0 {
		t.Errorf("rejected input still reached the service: %d/%d calls", c.encCall, c.decCall)
	}
}

func TestAWSKMSRef(t *testing.T) {
	t.Parallel()
	const arn = "arn:aws:kms:us-east-2:111122223333:key/1234abcd"
	for _, tc := range []struct{ keyID, region, want string }{
		{"alias/supermcp", "eu-west-1", "awskms:eu-west-1/alias/supermcp"},
		{"1234abcd-12ab-34cd-56ef", "us-east-2", "awskms:us-east-2/1234abcd-12ab-34cd-56ef"},
		{arn, "us-east-2", "awskms:" + arn},
	} {
		k := testKMS(t, newFakeKMS(), AWSKMSConfig{KeyID: tc.keyID, Region: tc.region})
		if k.Ref() != tc.want {
			t.Errorf("Ref() = %q, want %q", k.Ref(), tc.want)
		}
	}
	// With no deployment configured the binding falls back to the key
	// reference, which must still be stable and non-empty.
	k := testKMS(t, newFakeKMS(), AWSKMSConfig{})
	if k.encryptionContext()["deployment"] != k.Ref() {
		t.Errorf("default deployment = %q, want the key ref", k.encryptionContext()["deployment"])
	}
}

func TestNewAWSKMSConfigValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, cfg := range []AWSKMSConfig{
		{KeyID: "", Region: "eu-west-1"},
		{KeyID: "  ", Region: "eu-west-1"},
		{KeyID: "alias/x", Region: ""},
	} {
		if _, err := NewAWSKMSFromConfig(ctx, cfg); !errors.Is(err, ErrKMSConfig) {
			t.Errorf("%+v: err = %v, want ErrKMSConfig", cfg, err)
		}
	}
}

func TestAWSKMSVerify(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := newFakeKMS()
	if err := testKMS(t, c, AWSKMSConfig{}).Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	bad := newFakeKMS()
	bad.decErr = errKMSDown
	if err := testKMS(t, bad, AWSKMSConfig{}).Verify(ctx); !errors.Is(err, errKMSDown) {
		t.Fatalf("verify = %v, want the service error", err)
	}
}
