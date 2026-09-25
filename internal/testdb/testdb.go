// Package testdb names the databases tests create for themselves, so two
// checkouts of the repository can run their suites against one Postgres
// at the same time.
//
// A package whose tests own instance-wide state (signing keys, the
// instance data-key scope, the audit sequence) runs in a database of its
// own beside the one DATABASE_URL names. With a fixed name, two
// worktrees running `go test ./...` at once share that database and
// empty each other's tables mid-test. Name appends a suffix that is the
// same for every run from one checkout and different between checkouts:
// SUPERMCP_TEST_DB_SUFFIX when it is set, otherwise a short hash of the
// checkout's path. The browser suite (web/e2e/isolation.mjs) derives the
// same suffix the same way.
//
// Imported by tests only; nothing here reaches the binary.
package testdb

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// SuffixEnv overrides the derived suffix. Only lower-case letters, digits
// and underscores are kept, so the result is always a bare identifier.
const SuffixEnv = "SUPERMCP_TEST_DB_SUFFIX"

// maxSuffix keeps a name well inside Postgres's 63-byte identifier limit
// whatever an override says.
const maxSuffix = 20

var (
	once   sync.Once
	suffix string
)

// Name returns base with this checkout's suffix: base_<suffix>.
func Name(base string) string {
	return base + "_" + Suffix()
}

// Suffix is SUPERMCP_TEST_DB_SUFFIX, cleaned, or the first eight hex
// digits of the SHA-256 of the checkout's root directory.
func Suffix() string {
	once.Do(func() { suffix = derive(os.Getenv(SuffixEnv), root()) })
	return suffix
}

func derive(override, root string) string {
	if s := clean(override); s != "" {
		return s
	}
	sum := sha256.Sum256([]byte(root))
	return hex.EncodeToString(sum[:])[:8]
}

func clean(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
		if b.Len() == maxSuffix {
			break
		}
	}
	return b.String()
}

// root is the directory holding go.mod above the working directory, which
// under `go test` is the package being tested. Symlinks are resolved so a
// checkout reached two ways hashes once.
func root() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		if filepath.Dir(d) == d {
			return dir
		}
	}
}
