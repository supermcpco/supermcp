package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// envMap turns a table's settings into the getter KEKFromEnv reads, so a
// case states only what it sets and no test touches the real environment.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func b64Key(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func TestKEKFromEnvSelection(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		env  map[string]string
		// wantErr is a fragment of the message, and every failing case
		// names the setting an operator has to change.
		wantErr string
		check   func(t *testing.T, set *KEKSet)
	}{
		{
			name: "local by default",
			env:  map[string]string{envLocalKEK: b64Key(1)},
			check: func(t *testing.T, set *KEKSet) {
				if got := set.Active.Ref(); got != "local:env:ENCRYPTION_KEK" {
					t.Errorf("active ref = %q", got)
				}
				if len(set.Previous) != 0 {
					t.Errorf("previous = %d, want none", len(set.Previous))
				}
			},
		},
		{
			name: "local named explicitly",
			env:  map[string]string{envKEKProvider: "Local", envLocalKEK: b64Key(1)},
			check: func(t *testing.T, set *KEKSet) {
				if _, ok := set.Active.(*Local); !ok {
					t.Errorf("active is %T, want *Local", set.Active)
				}
			},
		},
		{
			name:    "local without material",
			env:     map[string]string{envKEKProvider: ProviderLocal},
			wantErr: envLocalKEK,
		},
		{
			name: "awskms",
			env: map[string]string{
				envKEKProvider:   ProviderAWSKMS,
				envKMSKeyID:      "alias/supermcp",
				envKMSRegion:     "eu-west-1",
				envKMSDeployment: "production",
				envKMSTimeout:    "3s",
			},
			check: func(t *testing.T, set *KEKSet) {
				k, ok := set.Active.(*AWSKMS)
				if !ok {
					t.Fatalf("active is %T, want *AWSKMS", set.Active)
				}
				if k.Ref() != "awskms:eu-west-1/alias/supermcp" {
					t.Errorf("active ref = %q", k.Ref())
				}
				if k.deployment != "production" || k.timeout.String() != "3s" {
					t.Errorf("deployment = %q, timeout = %s", k.deployment, k.timeout)
				}
			},
		},
		{
			name: "awskms takes the region from the platform",
			env: map[string]string{
				envKEKProvider: ProviderAWSKMS,
				envKMSKeyID:    "alias/supermcp",
				"AWS_REGION":   "us-east-2",
			},
			check: func(t *testing.T, set *KEKSet) {
				if got := set.Active.Ref(); got != "awskms:us-east-2/alias/supermcp" {
					t.Errorf("active ref = %q", got)
				}
			},
		},
		{
			name:    "awskms without a key id",
			env:     map[string]string{envKEKProvider: ProviderAWSKMS, envKMSRegion: "eu-west-1"},
			wantErr: envKMSKeyID,
		},
		{
			name:    "awskms without a region",
			env:     map[string]string{envKEKProvider: ProviderAWSKMS, envKMSKeyID: "alias/supermcp"},
			wantErr: envKMSRegion,
		},
		{
			name: "awskms with an unusable timeout",
			env: map[string]string{
				envKEKProvider: ProviderAWSKMS,
				envKMSKeyID:    "alias/supermcp",
				envKMSRegion:   "eu-west-1",
				envKMSTimeout:  "soon",
			},
			wantErr: envKMSTimeout,
		},
		{
			// A provider nobody recognises must not quietly become the
			// local one, even with perfectly good local material to hand:
			// that is how an installation ends up with its master key in
			// an environment variable it was configured not to use.
			name:    "unknown provider does not fall back",
			env:     map[string]string{envKEKProvider: "vault", envLocalKEK: b64Key(1)},
			wantErr: envKEKProvider,
		},
		{
			name: "previous key held for decrypt",
			env: map[string]string{
				envKEKProvider: ProviderAWSKMS,
				envKMSKeyID:    "alias/supermcp",
				envKMSRegion:   "eu-west-1",
				envKEKPrevious: b64Key(2),
			},
			check: func(t *testing.T, set *KEKSet) {
				if len(set.Previous) != 1 {
					t.Fatalf("previous = %d, want 1", len(set.Previous))
				}
				if got := set.Previous[0].Ref(); got != "local:env:ENCRYPTION_KEK" {
					t.Errorf("previous ref = %q", got)
				}
				if k, ok := set.Find("local:env:ENCRYPTION_KEK"); !ok || k != set.Previous[0] {
					t.Errorf("Find did not return the previous key")
				}
				if _, ok := set.Find("local:env:SOMETHING_ELSE"); ok {
					t.Errorf("Find matched a reference nothing holds")
				}
			},
		},
		{
			name: "previous keys keep the reference they were recorded under",
			env: map[string]string{
				envKEKProvider: ProviderAWSKMS,
				envKMSKeyID:    "alias/supermcp",
				envKMSRegion:   "eu-west-1",
				envKEKPrevious: "local:file:/keys/2025.key|" + b64Key(2) + ", file:/keys/2024.key|" + b64Key(3),
			},
			check: func(t *testing.T, set *KEKSet) {
				want := []string{"local:file:/keys/2025.key", "local:file:/keys/2024.key"}
				if len(set.Previous) != len(want) {
					t.Fatalf("previous = %d, want %d", len(set.Previous), len(want))
				}
				for i, ref := range want {
					if got := set.Previous[i].Ref(); got != ref {
						t.Errorf("previous[%d] ref = %q, want %q", i, got, ref)
					}
				}
			},
		},
		{
			name: "previous key sharing the active reference",
			env: map[string]string{
				envLocalKEK:    b64Key(1),
				envKEKPrevious: b64Key(2),
			},
			wantErr: envKEKPrevious,
		},
		{
			name: "previous key with unusable material",
			env: map[string]string{
				envLocalKEK:    b64Key(1),
				envKEKPrevious: "file:/keys/2024.key|not-base64",
			},
			wantErr: envKEKPrevious,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// The fake client keeps the KMS cases off the network; the
			// selection under test is the same either way.
			set, err := kekFromEnv(context.Background(), envMap(tc.env), AWSKMSConfig{Client: newFakeKMS()})
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("err = nil, want one naming %s", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to name %s", err, tc.wantErr)
				}
				if set != nil {
					t.Errorf("set = %+v, want nil beside an error", set)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			tc.check(t, set)
		})
	}
}

// TestPreviousKEKDecryptsButNeverSeals is the rotation invariant: an
// operator naming the outgoing key keeps every existing data key
// readable, and nothing new is ever wrapped by it.
func TestPreviousKEKDecryptsButNeverSeals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	old, current := testKEK(t, 1, "old"), testKEK(t, 2, "current")
	store := NewMemoryKeyStore()

	aad := AAD{Table: "t", Column: "c", RowID: "r1", OrgID: "o1"}
	ct, err := New(old, store).Seal(ctx, ScopeOrg("o1"), []byte("secret"), aad)
	if err != nil {
		t.Fatalf("seal under the old key: %v", err)
	}

	// A pod rolled onto the new master key still opens what the old one
	// wrapped, which is what lets the rollout happen while traffic runs.
	rolled := New(current, store, old)
	pt, err := rolled.Open(ctx, ct, aad)
	if err != nil || string(pt) != "secret" {
		t.Fatalf("open with the previous key: %q %v", pt, err)
	}

	// Sealing a scope that has no key yet mints one, and it is wrapped by
	// the active key alone.
	if _, err := rolled.Seal(ctx, ScopeOrg("o2"), []byte("fresh"), AAD{OrgID: "o2"}); err != nil {
		t.Fatalf("seal a new scope: %v", err)
	}
	dk, ok, err := store.Active(ctx, ScopeOrg("o2"))
	if err != nil || !ok {
		t.Fatalf("read the new data key: %v", err)
	}
	if dk.KEKRef != current.Ref() {
		t.Fatalf("new data key is wrapped by %q, want %q", dk.KEKRef, current.Ref())
	}

	// Without the old key the same ciphertext is refused, and the message
	// names the reference so an operator knows which key to supply.
	if _, err := New(current, store).Open(ctx, ct, aad); err == nil || !strings.Contains(err.Error(), old.Ref()) {
		t.Fatalf("open without the previous key = %v, want a message naming %s", err, old.Ref())
	}
}
