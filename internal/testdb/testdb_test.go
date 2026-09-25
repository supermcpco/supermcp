package testdb

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestDeriveOverrideIsCleaned(t *testing.T) {
	cases := map[string]string{
		"wt2":                        "wt2",
		"Feature-Branch/2":           "featurebranch2",
		"a_b":                        "a_b",
		"abcdefghijklmnopqrstuvwxyz": "abcdefghijklmnopqrst",
	}
	for in, want := range cases {
		if got := derive(in, "/ignored"); got != want {
			t.Errorf("derive(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDeriveHashesTheCheckout(t *testing.T) {
	a := derive("", "/home/dev/supermcp")
	b := derive("", "/home/dev/supermcp-wt/feature")
	if a == b {
		t.Fatalf("two checkouts share suffix %q", a)
	}
	if a != derive("", "/home/dev/supermcp") {
		t.Fatal("one checkout gave two suffixes")
	}
	// An override that cleans to nothing is no override.
	if got := derive("--/", "/home/dev/supermcp"); got != a {
		t.Fatalf("empty override gave %q, want the hash %q", got, a)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(a) {
		t.Fatalf("hash suffix %q is not eight hex digits", a)
	}
}

func TestRootFindsTheModule(t *testing.T) {
	r := root()
	if _, err := os.Stat(filepath.Join(r, "go.mod")); err != nil {
		t.Fatalf("root %q has no go.mod: %v", r, err)
	}
}

func TestNameIsAnIdentifier(t *testing.T) {
	n := Name("supermcp_mcpauth_keys_tests")
	if !regexp.MustCompile(`^supermcp_mcpauth_keys_tests_[a-z0-9_]+$`).MatchString(n) || len(n) > 63 {
		t.Fatalf("Name gave %q", n)
	}
}
