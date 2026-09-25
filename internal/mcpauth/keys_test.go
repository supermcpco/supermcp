// The keyring's rotation is a property of rows in signing_keys and of the
// order they change in, so it is tested against a live Postgres. Set
// DATABASE_URL to run it; the tests use a database of their own beside the
// one it names (see keysTestDB).
package mcpauth_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	neturl "net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// keysTestDB is the database these tests run in, created beside the one
// DATABASE_URL names.
//
// signing_keys is instance-wide: there is no organisation to partition it
// by, one active key serves the whole installation, and these tests empty
// the table and mint keys sealed by a master key and an in-memory key
// store only this process holds. `go test ./...` runs every package at
// once against DATABASE_URL, and the end-to-end tests mint their own
// active key there. Sharing the table, each side picked up the other's
// active key and could not unseal it ("ciphertext references an unknown
// data key"), or had its key deleted from under it.
//
// The convention, shared with supermcp_audit_tests and
// supermcp_rotate_tests: a test that owns instance-wide state (signing
// keys, the instance data-key scope, anything not keyed by an
// organisation) runs in a database of its package's own. Tests that only
// write rows under organisations they made up may share DATABASE_URL.
const keysTestDB = "supermcp_mcpauth_keys_tests"

func testKeyring(ctx context.Context, t *testing.T) (*mcpauth.Keyring, *tenant.DB) {
	t.Helper()
	url := ownDatabase(ctx, t)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	// The schema is applied as the maintenance role first: it is what
	// creates the row-level-security role the app pool connects as.
	maint, err := store.Open(ctx, url, url, log, store.Options{})
	if err != nil {
		t.Fatalf("could not open %s: %v", keysTestDB, err)
	}
	if err := maint.Migrate(ctx, true); err != nil {
		maint.Close()
		t.Fatalf("could not apply the schema to %s: %v", keysTestDB, err)
	}
	maint.Close()

	st, err := store.Open(ctx, url, url, log, store.Options{AppRole: true})
	if err != nil {
		t.Fatalf("could not open the pools: %v", err)
	}
	t.Cleanup(st.Close)
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	kek, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(raw), "keys-test")
	if err != nil {
		t.Fatal(err)
	}
	sealer := secrets.New(kek, secrets.NewMemoryKeyStore())
	k := mcpauth.NewKeyring(db, sealer, nil)
	k.Log = log

	// Every test here owns the whole table, which is safe only because the
	// database is this package's own (keysTestDB), so it starts from a
	// known empty one and leaves it that way.
	clear := func() {
		_ = db.Bypass(ctx, "keys test", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM signing_keys`)
			return err
		})
	}
	clear()
	t.Cleanup(clear)
	return k, db
}

// ownDatabase creates keysTestDB if it is not there and returns its URL.
// It is left behind between runs: creating it costs a second, and a
// developer who wants it gone can drop it.
func ownDatabase(ctx context.Context, t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set; key rotation can only be tested against a live Postgres")
	}
	u, err := neturl.Parse(url)
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
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, keysTestDB).Scan(&exists); err != nil {
		t.Fatalf("could not look for %s: %v", keysTestDB, err)
	}
	if !exists {
		// CREATE DATABASE cannot run in a transaction, and racing runs
		// both try: whoever loses sees "already exists", which is fine.
		if _, err := conn.Exec(ctx, `CREATE DATABASE `+keysTestDB); err != nil &&
			!strings.Contains(err.Error(), "already exists") {
			t.Fatalf("could not create %s: %v", keysTestDB, err)
		}
	}
	own := *u
	own.Path = "/" + keysTestDB
	return own.String()
}

func statuses(ctx context.Context, t *testing.T, db *tenant.DB) map[string]int {
	t.Helper()
	out := map[string]int{}
	err := db.Bypass(ctx, "keys test", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT status, count(*) FROM signing_keys GROUP BY status`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			var n int
			if err := rows.Scan(&s, &n); err != nil {
				return err
			}
			out[s] = n
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func age(ctx context.Context, t *testing.T, db *tenant.DB, status, interval string) {
	t.Helper()
	err := db.Bypass(ctx, "keys test", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE signing_keys
			SET created_at = now() - $2::interval, activated_at = CASE WHEN activated_at IS NULL THEN NULL ELSE now() - $2::interval END
			WHERE status = $1`, status, interval)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A key that is never rotated lives as long as the instance. Maintain is
// what moves it along, and it has to do nothing until there is something
// to do: publishing early is a rotation nobody asked for, and promoting
// early breaks every verifier that cached the key set before it.
func TestMaintainPublishesThenPromotes(t *testing.T) {
	ctx := context.Background()
	k, db := testKeyring(ctx, t)

	if err := k.Ensure(ctx); err != nil { // first boot mints the active key
		t.Fatal(err)
	}
	if got := statuses(ctx, t, db); got["active"] != 1 || got["next"] != 0 {
		t.Fatalf("after the first boot the table holds %v, wanted one active key", got)
	}

	if err := k.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if got := statuses(ctx, t, db); got["next"] != 0 {
		t.Fatalf("a fresh key was rotated straight away: %v", got)
	}

	// Ninety days on, the next key is published but not yet used.
	age(ctx, t, db, "active", "91 days")
	if err := k.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if got := statuses(ctx, t, db); got["active"] != 1 || got["next"] != 1 {
		t.Fatalf("an old key was not succeeded: %v", got)
	}

	// Still inside the pre-publish window, nothing moves.
	if err := k.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if got := statuses(ctx, t, db); got["active"] != 1 || got["next"] != 1 {
		t.Fatalf("the next key was promoted before clients could have fetched it: %v", got)
	}

	// A day later it takes over and the old key keeps verifying.
	age(ctx, t, db, "next", "2 days")
	if err := k.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	got := statuses(ctx, t, db)
	if got["active"] != 1 || got["retiring"] != 1 || got["next"] != 0 {
		t.Fatalf("after the window the table holds %v, wanted one active and one retiring key", got)
	}

	// Tokens signed now must verify, which is what the promotion was for.
	tok, err := k.Sign(ctx, map[string]any{"sub": "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Verify(ctx, tok); err != nil {
		t.Fatalf("a token signed by the promoted key does not verify: %v", err)
	}

	// And an anchor signature names the key that made it.
	sig, err := k.SignDigest(ctx, []byte("head"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) < 10 || !contains(sig, ":") {
		t.Errorf("a digest signature of %q does not name the key that made it", sig)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestVerifyDigestOutlivesRotation checks the signature the audit
// checkpoints carry. A checkpoint is kept for as long as the audit trail,
// so it has to verify after its key has been retired and left the JWKS.
func TestVerifyDigestOutlivesRotation(t *testing.T) {
	ctx := context.Background()
	k, db := testKeyring(ctx, t)

	hash := []byte("the head of the chain")
	sig, err := k.SignDigest(ctx, hash)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	if err := k.VerifyDigest(ctx, hash, sig); err != nil {
		t.Fatalf("a fresh signature did not verify: %v", err)
	}
	if err := k.VerifyDigest(ctx, []byte("another hash"), sig); err == nil {
		t.Fatal("a signature verified over a hash it was not made for")
	}

	// Retire every key. Nothing may unseal or mint one to verify.
	if err := db.Bypass(ctx, "keys test", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE signing_keys SET status = 'retired'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	offline := mcpauth.NewKeyring(db, nil, nil)
	if err := offline.VerifyDigest(ctx, hash, sig); err != nil {
		t.Fatalf("a signature by a retired key did not verify without a master key: %v", err)
	}

	kid, _, _ := strings.Cut(sig, ":")
	if err := offline.VerifyDigest(ctx, hash, "unknown"+sig[len(kid):]); err == nil {
		t.Fatal("a signature naming a key this instance never had verified")
	}
	if err := offline.VerifyDigest(ctx, hash, "no-separator"); err == nil {
		t.Fatal("a malformed signature verified")
	}
}
