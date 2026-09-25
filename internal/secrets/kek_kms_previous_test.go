package secrets

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// The two keys of a move, in the fake. Aliases resolve per region, as in
// KMS, so the entries name them the way an operator would.
const (
	oldKeyARN = "arn:aws:kms:eu-central-1:111122223333:key/11111111-1111-1111-1111-111111111111"
	newKeyARN = "arn:aws:kms:eu-central-1:111122223333:key/22222222-2222-2222-2222-222222222222"
	usKeyARN  = "arn:aws:kms:us-east-1:111122223333:key/33333333-3333-3333-3333-333333333333"
)

func moveKMS() *fakeKMS {
	f := newFakeKMS()
	f.aliases = map[string]string{
		"eu-central-1/alias/old": oldKeyARN,
		"eu-central-1/alias/new": newKeyARN,
		// The same alias name in another region, on an unrelated
		// single-Region key: what moving a key between regions looks like.
		"us-east-1/alias/new": usKeyARN,
		"us-east-1/alias/old": usKeyARN,
	}
	return f
}

// kmsEnv is the settings of an installation on alias/<active> in
// eu-central-1, with previous as SUPERMCP_KEK_PREVIOUS.
func kmsEnv(active, deployment, previous string) map[string]string {
	return map[string]string{
		envKEKProvider:   ProviderAWSKMS,
		envKMSKeyID:      active,
		envKMSRegion:     "eu-central-1",
		envKMSDeployment: deployment,
		envKEKPrevious:   previous,
	}
}

func setFrom(t *testing.T, f *fakeKMS, env map[string]string) *KEKSet {
	t.Helper()
	set, err := kekFromEnv(context.Background(), envMap(env), func(r string) KMSClient { return f.in(r) })
	if err != nil {
		t.Fatalf("build keys: %v", err)
	}
	return set
}

func TestPreviousKMSEntries(t *testing.T) {
	t.Parallel()
	type want struct{ ref, deployment string }
	for _, tc := range []struct {
		name     string
		env      map[string]string
		want     []want
		regions  []string // the regions a client was asked for, in order
		wantErrs string
	}{
		{
			name:    "an alias in the active key's region, with its deployment",
			env:     kmsEnv("alias/new", "prod", "awskms:alias/old"),
			want:    []want{{"awskms:eu-central-1/alias/old", "prod"}},
			regions: []string{"eu-central-1", "eu-central-1"},
		},
		{
			name:    "a region of its own",
			env:     kmsEnv("alias/new", "prod", "awskms:alias/old@us-east-1"),
			want:    []want{{"awskms:us-east-1/alias/old", "prod"}},
			regions: []string{"eu-central-1", "us-east-1"},
		},
		{
			name: "the reference pasted from data_keys",
			env:  kmsEnv("alias/new", "prod", "awskms:us-east-1/alias/old"),
			want: []want{{"awskms:us-east-1/alias/old", "prod"}},
		},
		{
			name:    "an ARN carries its region",
			env:     kmsEnv("alias/new", "prod", "awskms:"+usKeyARN),
			want:    []want{{"awskms:" + usKeyARN, "prod"}},
			regions: []string{"eu-central-1", "us-east-1"},
		},
		{
			name: "a deployment of its own",
			env:  kmsEnv("alias/new", "prod", "awskms:alias/old#prod-2024"),
			want: []want{{"awskms:eu-central-1/alias/old", "prod-2024"}},
		},
		{
			// The old key's deployment was never set, so its blobs carry
			// the old key's own reference; the new one fixes that.
			name: "a deployment that was never configured",
			env:  kmsEnv("alias/new", "prod", "awskms:alias/old#"),
			want: []want{{"awskms:eu-central-1/alias/old", "awskms:eu-central-1/alias/old"}},
		},
		{
			name: "KMS and local entries together, in order",
			env:  kmsEnv("alias/new", "prod", "awskms:alias/old, file:/keys/2024.key|"+b64Key(3)),
			want: []want{{"awskms:eu-central-1/alias/old", "prod"}, {"local:file:/keys/2024.key", ""}},
		},
		{
			name: "moving from KMS back to a local key",
			env: map[string]string{
				envLocalKEK: b64Key(1), envKMSRegion: "eu-central-1",
				envKEKPrevious: "awskms:alias/old",
			},
			want: []want{{"awskms:eu-central-1/alias/old", "awskms:eu-central-1/alias/old"}},
		},
		{
			// A non-multi-Region key cannot follow an installation into
			// another region; its successor there may well carry the same
			// alias name. They are different keys and the move is allowed.
			name: "the active alias name in another region",
			env:  kmsEnv("alias/new", "prod", "awskms:alias/new@us-east-1"),
			want: []want{{"awskms:us-east-1/alias/new", "prod"}},
		},

		{name: "the active key itself",
			env: kmsEnv("alias/new", "prod", "awskms:alias/new"), wantErrs: "is the active key"},
		{name: "the active key, as its stored reference",
			env: kmsEnv("alias/new", "prod", "awskms:eu-central-1/alias/new"), wantErrs: "is the active key"},
		{name: "the active key, as its ARN",
			env:      kmsEnv("22222222-2222-2222-2222-222222222222", "prod", "awskms:"+newKeyARN),
			wantErrs: "another spelling of the active key"},
		{name: "a multi-Region replica of the active key",
			env: kmsEnv(mrkID, "prod", "awskms:"+mrkID+"@us-west-2"), wantErrs: "multi-Region replica"},
		{name: "key material beside a KMS key",
			env: kmsEnv("alias/new", "prod", "awskms:alias/old|"+b64Key(2)), wantErrs: "no key material"},
		{name: "an ARN and a different region",
			env: kmsEnv("alias/new", "prod", "awskms:"+usKeyARN+"@eu-central-1"), wantErrs: "drop the @"},
		{name: "a region named twice",
			env: kmsEnv("alias/new", "prod", "awskms:us-east-1/alias/old@us-east-1"), wantErrs: "twice"},
		{name: "no key",
			env: kmsEnv("alias/new", "prod", "awskms:@us-east-1"), wantErrs: "key is empty"},
		{name: "an empty region",
			env: kmsEnv("alias/new", "prod", "awskms:alias/old@"), wantErrs: "region after @ is empty"},
		{name: "not an ARN",
			env: kmsEnv("alias/new", "prod", "awskms:arn:aws:s3:::bucket"), wantErrs: "not a KMS key"},
		{name: "one key named twice",
			env: kmsEnv("alias/new", "prod", "awskms:alias/old,awskms:eu-central-1/alias/old"), wantErrs: "twice"},
		{name: "a region after the deployment",
			env: kmsEnv("alias/new", "prod", "awskms:alias/old#prod@us-east-1"), wantErrs: "write @<region> before #<deployment>"},
		{name: "a misspelt region after @",
			env: kmsEnv("alias/new", "prod", "awskms:alias/old@eu-central1"), wantErrs: "not an AWS region"},
		{name: "an availability zone for a region",
			env: kmsEnv("alias/new", "prod", "awskms:alias/old@eu-central-1a"), wantErrs: "not an AWS region"},
		{name: "a misspelt region in a pasted reference",
			env: kmsEnv("alias/new", "prod", "awskms:eucentral-1/alias/old"), wantErrs: "not an AWS region"},
		{name: "a misspelt region in an ARN",
			env:      kmsEnv("alias/new", "prod", "awskms:arn:aws:kms:EU-central-1:111122223333:key/11111111-1111-1111-1111-111111111111"),
			wantErrs: "not an AWS region"},
		{name: "a misspelt region inherited from the settings",
			env: map[string]string{
				envLocalKEK: b64Key(1), envKMSRegion: "eu_central_1",
				envKEKPrevious: "awskms:alias/old",
			},
			wantErrs: "not an AWS region"},
		{name: "no region anywhere",
			env:      map[string]string{envLocalKEK: b64Key(1), envKEKPrevious: "awskms:alias/old"},
			wantErrs: "@<region>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var regions []string
			set, err := kekFromEnv(context.Background(), envMap(tc.env), func(r string) KMSClient {
				regions = append(regions, r)
				return newFakeKMS().in(r)
			})
			if tc.wantErrs != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrs) {
					t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErrs)
				}
				if !strings.Contains(err.Error(), envKEKPrevious) {
					t.Errorf("err = %v, want it to name %s", err, envKEKPrevious)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if len(set.Previous) != len(tc.want) {
				t.Fatalf("previous = %d keys, want %d", len(set.Previous), len(tc.want))
			}
			for i, w := range tc.want {
				k := set.Previous[i]
				if k.Ref() != w.ref {
					t.Errorf("previous[%d] = %s, want %s", i, k.Ref(), w.ref)
				}
				if a, ok := k.(*AWSKMS); ok && a.deployment != w.deployment {
					t.Errorf("previous[%d] deployment = %q, want %q", i, a.deployment, w.deployment)
				}
			}
			if tc.regions != nil && !slices.Equal(regions, tc.regions) {
				t.Errorf("clients made for %v, want %v", regions, tc.regions)
			}
		})
	}
}

// The heart of the card: data keys wrapped under one KMS key open on a
// process whose active key is another, through the previous entry, and
// each wrapped key goes to the key that made it and to no other.
func TestPreviousKMSKeyDecrypts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := moveKMS()
	store := newRotStore()
	aad := AAD{Table: "connector_credentials", Column: "value_enc", RowID: "c1/token", OrgID: "o1"}

	before := setFrom(t, f, kmsEnv("alias/old", "prod", ""))
	ct, err := New(before.Active, store).Seal(ctx, ScopeOrg("o1"), []byte("hunter2"), aad)
	if err != nil {
		t.Fatalf("seal under the old key: %v", err)
	}

	moved := setFrom(t, f, kmsEnv("alias/new", "prod", "awskms:alias/old"))
	sealer := New(moved.Active, store, moved.Previous...)
	f.mu.Lock()
	f.decKeys = nil
	f.mu.Unlock()
	pt, err := sealer.Open(ctx, ct, aad)
	if err != nil || string(pt) != "hunter2" {
		t.Fatalf("open through the previous key: %q %v", pt, err)
	}
	f.mu.Lock()
	got := slices.Clone(f.decKeys)
	f.mu.Unlock()
	if !slices.Equal(got, []string{oldKeyARN}) {
		t.Fatalf("decrypt went to %v, want the old key alone", got)
	}

	// A scope sealed for the first time is wrapped by the new key only.
	if _, err := sealer.Seal(ctx, ScopeOrg("o2"), []byte("fresh"), AAD{OrgID: "o2"}); err != nil {
		t.Fatalf("seal a new scope: %v", err)
	}
	if dk, _, _ := store.Active(ctx, ScopeOrg("o2")); dk.KEKRef != "awskms:eu-central-1/alias/new" {
		t.Fatalf("a new data key is wrapped by %s", dk.KEKRef)
	}

	// Without the entry the same ciphertext is refused, naming the key.
	alone := setFrom(t, f, kmsEnv("alias/new", "prod", ""))
	if _, err := New(alone.Active, store).Open(ctx, ct, aad); err == nil || !strings.Contains(err.Error(), "awskms:eu-central-1/alias/old") {
		t.Fatalf("open without the previous key = %v, want a refusal naming it", err)
	}
}

// A previous key opens with the encryption context it wrapped with. Its
// deployment follows SUPERMCP_KMS_DEPLOYMENT unless the entry names one,
// which is what lets a move also rename, or first name, the deployment.
func TestPreviousKMSKeyDeployment(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, oldDeployment, newDeployment, entry string
		opens                                     bool
	}{
		{"shared deployment", "prod", "prod", "awskms:alias/old", true},
		{"renamed, entry says the old name", "prod-2024", "prod", "awskms:alias/old#prod-2024", true},
		{"renamed, entry silent", "prod-2024", "prod", "awskms:alias/old", false},
		{"first named now, entry says it was unset", "", "prod", "awskms:alias/old#", true},
		{"first named now, entry silent", "", "prod", "awskms:alias/old", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			f := moveKMS()
			store := newRotStore()
			aad := AAD{Table: "t", Column: "c", RowID: "r", OrgID: "o1"}
			before := setFrom(t, f, kmsEnv("alias/old", tc.oldDeployment, ""))
			ct, err := New(before.Active, store).Seal(ctx, ScopeOrg("o1"), []byte("x"), aad)
			if err != nil {
				t.Fatal(err)
			}
			moved := setFrom(t, f, kmsEnv("alias/new", tc.newDeployment, tc.entry))
			_, err = New(moved.Active, store, moved.Previous...).Open(ctx, ct, aad)
			if tc.opens && err != nil {
				t.Fatalf("open: %v", err)
			}
			if !tc.opens && (err == nil || !strings.Contains(err.Error(), "encryption context mismatch")) {
				t.Fatalf("open = %v, want the encryption context refused", err)
			}
		})
	}
}

// rotate-kek moves every data key, of every scope and status, from one KMS
// key to the other; verify's report then shows each under the active key;
// the new key alone opens everything; the old key alone opens nothing.
func TestRotateKEKBetweenKMSKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := moveKMS()
	store := newRotStore()

	before := setFrom(t, f, kmsEnv("alias/old", "prod", ""))
	sealed := seedScopes(t, New(before.Active, store), ScopeInstance, ScopeOrg("o1"), ScopeOrg("o2"))
	// A superseded data key has to move too: a backup restored later
	// still holds rows sealed under it.
	o1, _, _ := store.Active(ctx, ScopeOrg("o1"))
	if err := store.SetDataKeyStatus(ctx, o1.ID, statusDecryptOnly); err != nil {
		t.Fatal(err)
	}
	seedScopes(t, New(before.Active, store), ScopeOrg("o1"))

	moved := setFrom(t, f, kmsEnv("alias/new", "prod", "awskms:alias/old"))
	keys, _ := store.ListDataKeys(ctx)
	checks, err := moved.Check(ctx, keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if c.Err != nil || c.Active || c.HeldBy != HeldByPrevious {
			t.Fatalf("before the rotation %s: active=%v held by %q err=%v, want previous", c.Key.Scope, c.Active, c.HeldBy, c.Err)
		}
	}

	rep, err := RotateKEK(ctx, KEKRotation{Store: store, To: moved.Active, From: moved.Previous})
	if err != nil || rep.ReWrapped != len(keys) || rep.Skipped != 0 {
		t.Fatalf("rotate: %+v %v, want %d re-wrapped", rep, err, len(keys))
	}
	keys, _ = store.ListDataKeys(ctx)
	checks, err = moved.Check(ctx, keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if c.Err != nil || !c.Active || c.HeldBy != HeldByActive {
			t.Fatalf("after the rotation %s (%s): active=%v held by %q err=%v", c.Key.Scope, c.Key.Status, c.Active, c.HeldBy, c.Err)
		}
	}
	// Running it again finds nothing to do.
	if rep, err := RotateKEK(ctx, KEKRotation{Store: store, To: moved.Active, From: moved.Previous}); err != nil || rep.Skipped != len(keys) {
		t.Fatalf("second run: %+v %v", rep, err)
	}

	// The new key on its own opens every value sealed before the move,
	// o1's under the data key it has since superseded included.
	alone := setFrom(t, f, kmsEnv("alias/new", "prod", ""))
	s := New(alone.Active, store)
	for scope, ct := range sealed {
		aad := AAD{Table: "t", Column: "c", RowID: scope, OrgID: scope}
		if got, err := s.Open(ctx, ct, aad); err != nil || string(got) != "secret-"+scope {
			t.Fatalf("%s under the new key alone: %q %v", scope, got, err)
		}
	}

	// And the old key on its own opens none, even when told the data key
	// is its own: KMS refuses a blob the pinned key did not make.
	old := setFrom(t, f, kmsEnv("alias/old", "prod", ""))
	checks, err = old.Check(ctx, keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if c.Err == nil || c.HeldBy != "" {
			t.Fatalf("the old key alone reported %s as opening (held by %q)", c.Key.Scope, c.HeldBy)
		}
	}
	forged := *keys[0]
	forged.KEKRef = old.Active.Ref()
	err = openAndDiscard(ctx, old.Active, forged.Wrapped)
	if err == nil || !strings.Contains(err.Error(), "IncorrectKeyException") {
		t.Fatalf("the old key opened a data key the new one wrapped: %v", err)
	}
	if !errors.Is(err, ErrKeyRefused) || errors.Is(err, ErrKeyServiceUnavailable) {
		t.Fatalf("a wrong key is %v, want ErrKeyRefused and not unavailable", err)
	}
}

// The order is fixed: exact references first, the active key's and then
// each previous key's, and only then a cross-region match. With one alias
// name on unrelated keys in two regions, the cross-region guess would be
// the wrong key.
func TestPreviousKMSExactReferenceWins(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := moveKMS()
	store := newRotStore()
	aad := AAD{Table: "t", Column: "c", RowID: "r", OrgID: "o1"}

	us := regionKMS(t, f, "alias/new", "us-east-1", "prod")
	ct, err := New(us, store).Seal(ctx, ScopeOrg("o1"), []byte("x"), aad)
	if err != nil {
		t.Fatal(err)
	}
	moved := setFrom(t, f, kmsEnv("alias/new", "prod", "awskms:alias/new@us-east-1"))
	f.mu.Lock()
	f.decKeys = nil
	f.mu.Unlock()
	if _, err := New(moved.Active, store, moved.Previous...).Open(ctx, ct, aad); err != nil {
		t.Fatalf("open: %v", err)
	}
	f.mu.Lock()
	got := slices.Clone(f.decKeys)
	f.mu.Unlock()
	if !slices.Equal(got, []string{usKeyARN}) {
		t.Fatalf("decrypt went to %v, want the us-east-1 key alone", got)
	}
	keys, _ := store.ListDataKeys(ctx)
	if k, ok := moved.Find(keys[0].KEKRef); !ok || k != moved.Previous[0] {
		t.Fatalf("Find chose %v, want the previous key", k)
	}
}

// Check reports a key nothing in the set can open as such, and a replica's
// data key as held by the replica rule rather than by name.
func TestKEKSetCheckReportsHolder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFakeKMS()
	store := newRotStore()
	eu := regionKMS(t, f, mrkID, "eu-central-1", "prod")
	seedScopes(t, New(eu, store), ScopeInstance)
	us := regionKMS(t, f, mrkID, "us-west-2", "prod")
	keys, _ := store.ListDataKeys(ctx)
	stray := &DataKey{Scope: ScopeOrg("o9"), KEKRef: "awskms:eu-central-1/alias/gone", Wrapped: []byte("blob"), Status: "active"}

	checks, err := (&KEKSet{Active: us}).Check(ctx, append(keys, stray))
	if err != nil {
		t.Fatal(err)
	}
	if c := checks[0]; c.Err != nil || c.Active || c.HeldBy != HeldByReplica {
		t.Errorf("replica's key: active=%v held by %q err=%v", c.Active, c.HeldBy, c.Err)
	}
	if c := checks[1]; c.Err == nil || c.HeldBy != "" {
		t.Errorf("stray key: held by %q err=%v, want no holder", c.HeldBy, c.Err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (&KEKSet{Active: us}).Check(cancelled, keys); !errors.Is(err, context.Canceled) {
		t.Errorf("check on a cancelled context = %v", err)
	}
}

// A KMS entry never carries key material, but an operator can still paste
// one after a "|" by mistake. The boot error that refuses it goes to pod
// logs, so it names the entry without the material.
func TestPreviousKMSEntryErrorOmitsMaterial(t *testing.T) {
	t.Parallel()
	material := b64Key(7)
	for _, entry := range []string{
		"awskms:alias/old|" + material,
		"awskms:alias/old@eu-central1|" + material,
		"awskms:alias/old#prod|" + material,
	} {
		_, err := kekFromEnv(context.Background(), envMap(kmsEnv("alias/new", "prod", entry)),
			func(r string) KMSClient { return newFakeKMS().in(r) })
		if err == nil {
			t.Fatalf("%s: accepted", entry)
		}
		if msg := err.Error(); strings.Contains(msg, material) || strings.Contains(msg, "|") {
			t.Fatalf("the error for an entry with key material quotes it: %s", msg)
		}
	}
}

// A previous entry that names its region opens its own reference and no
// other: the alias rule that lets a key open a same-named alias's data
// keys in another region does not apply to it.
func TestPreviousKMSPinnedRegionSkipsCrossRegion(t *testing.T) {
	t.Parallel()
	f := moveKMS()
	elsewhere := "awskms:eu-west-2/alias/old"

	pinned := setFrom(t, f, kmsEnv("alias/new", "prod", "awskms:alias/old@us-east-1"))
	if k, ok := pinned.Find(elsewhere); ok {
		t.Fatalf("a region-pinned previous key took %s as %s", elsewhere, k.Ref())
	}
	if _, ok := pinned.Find("awskms:us-east-1/alias/old"); !ok {
		t.Fatal("a region-pinned previous key no longer opens its own reference")
	}

	// Without a region the entry behaves like the active key does.
	loose := setFrom(t, f, kmsEnv("alias/new", "prod", "awskms:alias/old"))
	if _, ok := loose.Find(elsewhere); !ok {
		t.Fatalf("an unpinned previous key does not take %s", elsewhere)
	}
}
