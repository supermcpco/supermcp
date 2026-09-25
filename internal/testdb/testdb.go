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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/store"
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

// Own returns the URL of a database named name on the server DATABASE_URL
// (base) points at, created and migrated if it is not already. It is
// kept between runs on purpose.
//
// Creation and the first migration run under one advisory lock on the
// server's postgres database, held on the admin connection. Without it,
// packages that own a database each run migration 00002 at the same
// moment on a fresh server, and its CREATE ROLE supermcp_app races
// across databases: the role is per server, the IF NOT EXISTS check is
// per statement, and the loser fails with a duplicate pg_authid key.
// The lock is per server too, so it also covers a second checkout's run.
//
// The test is skipped when Postgres cannot be reached, and fails when it
// can and the database cannot be prepared.
func Own(ctx context.Context, t *testing.T, base, name string) string {
	t.Helper()
	if base == "" {
		t.Skip("DATABASE_URL is not set")
	}
	u, err := neturl.Parse(base)
	if err != nil {
		t.Fatalf("DATABASE_URL is not a URL: %v", err)
	}
	admin := *u
	admin.Path = "/postgres"
	conn, err := pgx.Connect(ctx, admin.String())
	if err != nil {
		t.Skipf("could not reach Postgres to make this package's own database: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	// A session lock, released below or when the connection closes.
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('supermcp:testdb'))`); err != nil {
		t.Fatalf("could not take the test-database lock: %v", err)
	}
	defer func() { _, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock(hashtext('supermcp:testdb'))`) }()

	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, name).Scan(&exists); err != nil {
		t.Fatalf("could not look for %s: %v", name, err)
	}
	if !exists {
		// CREATE DATABASE cannot run in a transaction; under the lock
		// nothing else creates it, but "already exists" stays harmless.
		if _, err := conn.Exec(ctx, `CREATE DATABASE `+name); err != nil &&
			!strings.Contains(err.Error(), "already exists") {
			t.Fatalf("could not create %s: %v", name, err)
		}
	}
	own := *u
	own.Path = "/" + name
	st, err := store.Open(ctx, own.String(), own.String(), slog.New(slog.DiscardHandler), store.Options{})
	if err != nil {
		t.Fatalf("could not open %s: %v", name, err)
	}
	defer st.Close()
	if err := st.Migrate(ctx, true); err != nil {
		t.Fatalf("could not apply the schema to %s: %v", name, err)
	}
	return own.String()
}
