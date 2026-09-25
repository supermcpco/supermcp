package secrets

import (
	"context"
	"strings"
	"testing"
)

const (
	mrkID       = "mrk-1234abcd12ab34cd56ef1234567890ab"
	mrkARNEU    = "arn:aws:kms:eu-central-1:111122223333:key/" + mrkID
	mrkARNUS    = "arn:aws:kms:us-west-2:111122223333:key/" + mrkID
	mrkARNOther = "arn:aws:kms:us-west-2:444455556666:key/" + mrkID
	singleID    = "1234abcd-12ab-34cd-56ef-1234567890ab"
)

// A database restored into another region still names the region its data
// keys were wrapped in. With a multi-Region key the replica in the new
// region can open them, and nothing but the region may differ: the same
// key id, account and partition, and the same deployment.
func TestAWSKMSOpensDataKeysWrappedInAnotherRegion(t *testing.T) {
	t.Parallel()
	type side struct {
		keyID, region, deployment string
	}
	cases := []struct {
		name    string
		wrap    side
		open    side
		aliases map[string]string // "<region>/<alias>" -> key
		want    string            // empty: opens; otherwise part of the error
	}{
		{name: "multi-Region key id, deployment left unset",
			wrap: side{mrkID, "eu-central-1", ""}, open: side{mrkID, "us-west-2", ""}},
		{name: "multi-Region key id, the same deployment",
			wrap: side{mrkID, "eu-central-1", "prod"}, open: side{mrkID, "us-west-2", "prod"}},
		{name: "multi-Region key ARN, the replica's ARN",
			wrap: side{mrkARNEU, "eu-central-1", ""}, open: side{mrkARNUS, "us-west-2", ""}},
		{name: "an alias that points at the replica in the new region",
			wrap: side{"alias/supermcp", "eu-central-1", ""}, open: side{"alias/supermcp", "us-west-2", ""},
			aliases: map[string]string{"eu-central-1/alias/supermcp": mrkARNEU, "us-west-2/alias/supermcp": mrkARNUS}},
		{name: "an alias that points at an unrelated key there is refused by KMS",
			wrap: side{"alias/supermcp", "eu-central-1", ""}, open: side{"alias/supermcp", "us-west-2", ""},
			aliases: map[string]string{"eu-central-1/alias/supermcp": mrkARNEU, "us-west-2/alias/supermcp": "arn:aws:kms:us-west-2:111122223333:key/" + singleID},
			want:    "IncorrectKeyException"},
		{name: "a single-Region key exists in one region only",
			wrap: side{singleID, "eu-central-1", ""}, open: side{singleID, "us-west-2", ""},
			want: "does not hold"},
		{name: "a replica is in the same account",
			wrap: side{mrkARNEU, "eu-central-1", ""}, open: side{mrkARNOther, "us-west-2", ""},
			want: "does not hold"},
		{name: "a different deployment is a different installation",
			wrap: side{mrkID, "eu-central-1", "prod"}, open: side{mrkID, "us-west-2", "staging"},
			want: "encryption context mismatch"},
		{name: "a deployment set on one side only",
			wrap: side{mrkID, "eu-central-1", ""}, open: side{mrkID, "us-west-2", "prod"},
			want: "encryption context mismatch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			f := newFakeKMS()
			f.aliases = c.aliases
			origin := regionKMS(t, f, c.wrap.keyID, c.wrap.region, c.wrap.deployment)
			restored := regionKMS(t, f, c.open.keyID, c.open.region, c.open.deployment)

			store := newRotStore()
			aad := AAD{Table: "t", Column: "c", RowID: "r", OrgID: "o1"}
			ct, err := New(origin, store).Seal(ctx, ScopeOrg("o1"), []byte("hunter2"), aad)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}

			pt, err := New(restored, store).Open(ctx, ct, aad)
			if c.want != "" {
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("opened with %v, want an error mentioning %q", err, c.want)
				}
				return
			}
			if err != nil || string(pt) != "hunter2" {
				t.Fatalf("open under %s: %q %v", restored.Ref(), pt, err)
			}

			// keys verify finds the key the same way the sealer does.
			set := &KEKSet{Active: Observed(restored, func(string, string, error) {})}
			dks, _ := store.ListDataKeys(ctx)
			if _, ok := set.Find(dks[0].KEKRef); !ok {
				t.Fatalf("KEKSet.Find does not take %s for %s", restored.Ref(), dks[0].KEKRef)
			}

			// And rotate-kek moves the data keys onto this region's
			// reference, after which they open by exact match.
			rep, err := RotateKEK(ctx, KEKRotation{Store: store, To: restored})
			if err != nil || rep.ReWrapped != 1 {
				t.Fatalf("rotate onto %s: %+v %v", restored.Ref(), rep, err)
			}
			dks, _ = store.ListDataKeys(ctx)
			if dks[0].KEKRef != restored.Ref() {
				t.Fatalf("the data key records %s after the rotation, want %s", dks[0].KEKRef, restored.Ref())
			}
			if pt, err := New(restored, store).Open(ctx, ct, aad); err != nil || string(pt) != "hunter2" {
				t.Fatalf("open after the rotation: %q %v", pt, err)
			}
		})
	}
}

// The region-free comparison, on its own. Only the region may differ, and
// only for what AWS replicates (a multi-Region key) or lets the operator
// recreate by name (an alias).
func TestKMSRefRelated(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b string
		want bool
	}{
		{"awskms:eu-central-1/" + mrkID, "awskms:us-west-2/" + mrkID, true},
		{"awskms:" + mrkARNEU, "awskms:" + mrkARNUS, true},
		{"awskms:" + mrkARNEU, "awskms:us-west-2/" + mrkID, true},
		{"awskms:eu-central-1/alias/supermcp", "awskms:us-west-2/alias/supermcp", true},
		{"awskms:eu-central-1/" + mrkID, "awskms:eu-central-1/" + mrkID, false}, // same reference: not this path
		{"awskms:eu-central-1/" + singleID, "awskms:us-west-2/" + singleID, false},
		{"awskms:eu-central-1/alias/supermcp", "awskms:us-west-2/alias/other", false},
		{"awskms:" + mrkARNEU, "awskms:" + mrkARNOther, false},
		{"awskms:" + mrkARNEU, "awskms:" + strings.Replace(mrkARNUS, "arn:aws:", "arn:aws-cn:", 1), false},
		{"awskms:eu-central-1/" + mrkID, "local:env:ENCRYPTION_KEK", false},
		{"awskms:" + mrkID, "awskms:us-west-2/" + mrkID, false}, // not something awsKMSRef writes
	}
	for _, c := range cases {
		a, okA := parseKMSRef(c.a)
		b, okB := parseKMSRef(c.b)
		if got := okA && okB && a.relatedTo(b); got != c.want {
			t.Errorf("%s ~ %s = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func regionKMS(t *testing.T, f *fakeKMS, keyID, region, deployment string) *AWSKMS {
	t.Helper()
	k, err := NewAWSKMSFromConfig(context.Background(), AWSKMSConfig{
		KeyID: keyID, Region: region, Deployment: deployment, Client: f.in(region),
	})
	if err != nil {
		t.Fatal(err)
	}
	return k
}
