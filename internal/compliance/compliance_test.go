// These tests cover the parts of a report that are decisions rather than
// queries: what counts as a secret, what a credential's scopes leave of
// its owner's permissions, and what one person's pseudonym is. The parts
// that are queries are tested against a live Postgres in the files beside
// this one.
package compliance

import (
	"strings"
	"testing"
	"time"

	"github.com/supermcpco/supermcp/internal/authz"
)

func TestDigestHidesTheValueAndDistinguishesTwo(t *testing.T) {
	a, b := Digest("hunter2"), Digest("hunter3")
	switch {
	case strings.Contains(a, "hunter"):
		t.Fatalf("the digest %q contains the value it is meant to replace", a)
	case a == b:
		t.Fatalf("two different values digested the same (%q), so a reader could not tell a rotation happened", a)
	case Digest("hunter2") != a:
		t.Fatal("the same value digested differently twice, so two runs of a report could not be compared")
	case Digest("") != "":
		t.Fatalf("an empty value digested to %q; an absent setting should read as absent, not as a secret", Digest(""))
	}
}

func TestRedactURLKeepsWhatDecidesBehaviour(t *testing.T) {
	got := RedactURL("postgres://supermcp:s3cret@db.internal:5432/supermcp?sslmode=disable")
	switch {
	case strings.Contains(got, "s3cret"):
		t.Fatalf("the password survived redaction: %q", got)
	case !strings.Contains(got, "sslmode=disable"):
		t.Fatalf("whether the connection is encrypted was redacted away, which is the one thing an assessor needs: %q", got)
	case !strings.Contains(got, "db.internal:5432"):
		t.Fatalf("the host was redacted away: %q", got)
	case !strings.Contains(got, "sha256:"):
		t.Fatalf("the password was removed rather than digested, so two instances cannot be compared: %q", got)
	}
	// A string with no credentials is not a secret and is left alone.
	plain := "redis://localhost:6379"
	if RedactURL(plain) != plain {
		t.Fatalf("a URL with no password was altered: %q", RedactURL(plain))
	}
}

func TestLooksSecretErrsTowardsRedaction(t *testing.T) {
	for _, name := range []string{"ENCRYPTION_KEK", "SUPERMCP_KEK_PREVIOUS", "clientSecret", "API_TOKEN", "db_password"} {
		if !looksSecret(name) {
			t.Errorf("%s was not treated as a secret; a secret printed in a snapshot costs a rotation", name)
		}
	}
	for _, name := range []string{"SUPERMCP_LISTEN", "logFormat", "dcrMode"} {
		if looksSecret(name) {
			t.Errorf("%s was digested; a setting nobody can read is a setting nobody can review", name)
		}
	}
}

func TestEffectiveIgnoresExpiredAndScopedBindings(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	got := effective([]Binding{
		{ScopeKind: "org", Permissions: []string{"org:read"}},
		{ScopeKind: "org", Permissions: []string{"roles:manage"}, ExpiresAt: &past},
		{ScopeKind: "org", Permissions: []string{"audit:read"}, ExpiresAt: &future},
		{ScopeKind: "server", Permissions: []string{"servers:delete"}},
	}, now)
	want := []string{"audit:read", "org:read"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("effective permissions were %v, want %v: an expired binding grants nothing and a server-scoped one does not widen the workspace", got, want)
	}
}

func TestEffectiveExpandsTheWildcard(t *testing.T) {
	now := time.Now()
	got := effective([]Binding{{ScopeKind: "org", Permissions: []string{string(authz.Wildcard)}}}, now)
	if len(got) != len(authz.All())+1 {
		t.Fatalf("the wildcard expanded to %d permissions, want the whole closed set of %d plus the wildcard itself",
			len(got), len(authz.All()))
	}
}

func TestNarrowByScopesMatchesTheEvaluator(t *testing.T) {
	owner := []string{"org:read", "roles:manage", "tools:read", "tools:invoke", "tools:invoke:destructive"}
	cases := []struct {
		name   string
		scopes []string
		want   string
	}{
		{"no scopes leaves the owner's set alone", nil, "org:read roles:manage tools:read tools:invoke tools:invoke:destructive"},
		{"the org scope leaves it alone", []string{authz.ScopeOrg}, "org:read roles:manage tools:read tools:invoke tools:invoke:destructive"},
		{"read only", []string{authz.ScopeToolsRead}, "tools:read"},
		{"invoke implies read", []string{authz.ScopeToolsInvoke}, "tools:read tools:invoke tools:invoke:destructive"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(narrowByScopes(owner, c.scopes), " ")
			if got != c.want {
				t.Fatalf("a credential with scopes %v resolved to %q, want %q", c.scopes, got, c.want)
			}
		})
	}
}

func TestPseudonymIsStableAndUnique(t *testing.T) {
	a, b := Pseudonym("u_1"), Pseudonym("u_2")
	switch {
	case a == b:
		t.Fatal("two accounts pseudonymised to the same name, which would break the unique index on the address")
	case Pseudonym("u_1") != a:
		t.Fatal("the pseudonym is not stable, so a second erasure would rewrite what the first one wrote")
	case strings.Contains(PseudonymAddress("u_1"), "@erased.invalid") == false:
		t.Fatalf("the address %q is not in a domain that can never be delivered to", PseudonymAddress("u_1"))
	}
}

// The columns an erasure rewrites in audit_events are the ones the chain
// hash does not cover. This test is the guard on that list: adding a
// column here that the hash covers would break every stream in the field,
// and would do it quietly until somebody ran a verification.
func TestOnlyDisplayColumnsAreRewrittenInTheAuditStream(t *testing.T) {
	hashed := map[string]bool{
		"id": true, "ts": true, "organization_id": true, "category": true, "action": true,
		"outcome": true, "actor_kind": true, "actor_id": true, "target_kind": true, "target_id": true,
		"content_hash": true, "diff": true, "payload": true, "meta": true,
	}
	for _, target := range eraseTargets {
		if target.table != "audit_events" {
			continue
		}
		for _, col := range target.columns {
			if hashed[col] {
				t.Fatalf("the erasure rewrites audit_events.%s, which the chain hash covers; every row after it would fail verification", col)
			}
		}
		if strings.Join(target.columns, ",") != strings.Join(ChainSafeColumns(), ",") {
			t.Fatalf("the documented safe columns %v no longer match what the erasure rewrites %v",
				ChainSafeColumns(), target.columns)
		}
	}
}

func TestWrapDoesNotLoseWords(t *testing.T) {
	in := "one two three four five six seven eight nine ten"
	got := wrap(in, 12, "  ")
	if strings.Join(strings.Fields(got), " ") != in {
		t.Fatalf("wrapping changed the words: %q", got)
	}
	if !strings.Contains(got, "\n  ") {
		t.Fatalf("a line longer than the width was not wrapped: %q", got)
	}
}
