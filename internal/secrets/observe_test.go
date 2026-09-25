package secrets

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// kekCalls records what an observer is told, keyed "provider/op/outcome".
type kekCalls struct {
	mu sync.Mutex
	n  map[string]int
}

func (c *kekCalls) observe(provider, op string, err error) {
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n = map[string]int{}
	}
	c.n[provider+"/"+op+"/"+outcome]++
}

func (c *kekCalls) get(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[key]
}

// What reaches the observer is what reaches KMS: one wrap for a new data
// key, one unwrap per cold cache, and nothing for the decryptions a warm
// cache answers. That is what makes an error count here mean "KMS failed
// something that needed it".
func TestObservedCountsKMSTrafficNotDecryptions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fake := newFakeKMS()
	var calls kekCalls
	kek := Observed(testKMS(t, fake, AWSKMSConfig{}), calls.observe)
	if kek.Ref() == "" || ProviderOf(kek.Ref()) != ProviderAWSKMS {
		t.Fatalf("the observed key's reference %q no longer names its provider", kek.Ref())
	}
	store := NewMemoryKeyStore()
	aad := AAD{Table: "t", Column: "c", RowID: "r", OrgID: "o"}

	ct, err := New(kek, store).Seal(ctx, ScopeOrg("o"), []byte("secret"), aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	cold := New(kek, store)
	for range 5 {
		if _, err := cold.Open(ctx, ct, aad); err != nil {
			t.Fatalf("Open: %v", err)
		}
	}
	if got := calls.get("awskms/wrap/ok"); got != 1 {
		t.Errorf("wraps = %d, want 1 for the one data key minted", got)
	}
	if got := calls.get("awskms/unwrap/ok"); got != 1 {
		t.Errorf("unwraps = %d, want 1: five opens on one cache are one KMS call", got)
	}

	// KMS goes away. A process that has not unwrapped the key yet has to
	// ask, and every ask fails.
	fake.mu.Lock()
	fake.decErr = errKMSDown
	fake.mu.Unlock()
	restarted := New(kek, store)
	for range 3 {
		if _, err := restarted.Open(ctx, ct, aad); !errors.Is(err, errKMSDown) {
			t.Fatalf("Open with KMS down = %v, want %v", err, errKMSDown)
		}
	}
	if got := calls.get("awskms/unwrap/error"); got != 3 {
		t.Errorf("unwrap errors = %d, want 3", got)
	}
}

// stubKEK fails every call with the context's error, or err if the
// context is still live.
type stubKEK struct {
	ref string
	err error
}

func (s stubKEK) Ref() string { return s.ref }
func (s stubKEK) Wrap(ctx context.Context, _ []byte) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, s.err
}

func (s stubKEK) Unwrap(ctx context.Context, _ []byte) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, s.err
}

func TestObservedIgnoresCallersThatGaveUp(t *testing.T) {
	t.Parallel()
	var calls kekCalls
	kek := Observed(stubKEK{ref: "awskms:eu-west-1/alias/x", err: errKMSDown}, calls.observe)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = kek.Unwrap(cancelled, []byte("x"))
	_, _ = kek.Wrap(cancelled, []byte("x"))
	if got := calls.get("awskms/unwrap/error") + calls.get("awskms/wrap/error"); got != 0 {
		t.Errorf("a cancelled caller was counted %d times as a KMS error", got)
	}

	_, _ = kek.Unwrap(context.Background(), []byte("x"))
	if got := calls.get("awskms/unwrap/error"); got != 1 {
		t.Errorf("unwrap errors = %d, want 1 for a live caller", got)
	}
}

func TestProviderOf(t *testing.T) {
	t.Parallel()
	tests := []struct{ ref, want string }{
		{"awskms:eu-west-1/alias/supermcp", ProviderAWSKMS},
		{"awskms:arn:aws:kms:eu-west-1:1:key/abc", ProviderAWSKMS},
		{"local:env:ENCRYPTION_KEK", ProviderLocal},
		{"local:file:/run/kek", ProviderLocal},
		{"gcpkms:projects/x", ""},
		{"", ""},
	}
	for _, tc := range tests {
		if got := ProviderOf(tc.ref); got != tc.want {
			t.Errorf("ProviderOf(%q) = %q, want %q", tc.ref, got, tc.want)
		}
	}
}

func TestObservedPassesNilThrough(t *testing.T) {
	t.Parallel()
	if Observed(nil, func(string, string, error) {}) != nil {
		t.Error("observing no key produced a key")
	}
	k, err := NewLocal("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "test")
	if err != nil {
		t.Fatal(err)
	}
	if Observed(k, nil) != KEK(k) {
		t.Error("with no observer the key should be returned as it is")
	}
}
