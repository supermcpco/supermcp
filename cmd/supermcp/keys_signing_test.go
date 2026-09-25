package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	neturl "net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/store"
)

// Everything rotate-signing refuses before it opens a database.
func TestKeysRotateSigningRefusesBadArgumentsBeforeTouchingTheDatabase(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://nobody@127.0.0.1:1/none")
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"rotate-signing", "now"}, `unexpected argument "now"`},
		{[]string{"rotate-signing", "-revoke", "extra"}, `unexpected argument "extra"`},
		{[]string{"rotate-signing", "-format", "csv"}, `unknown format "csv"`},
		{[]string{"rotate-signing", "-force"}, "flag provided but not defined: -force"},
		{[]string{"rotate-signing", "-revoke=maybe"}, `invalid boolean value "maybe"`},
	}
	for _, c := range cases {
		err := keysCmd(c.args)
		if err == nil {
			t.Errorf("%v: accepted", c.args)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: got %q, want it to mention %q", c.args, err, c.want)
		}
	}
}

func TestKeysRotateSigningOutput(t *testing.T) {
	t.Parallel()
	since := time.Date(2026, 9, 25, 8, 30, 0, 0, time.UTC)
	from := since.Add(24 * time.Hour)
	cases := []struct {
		name string
		r    signingRotation
		want []string
	}{
		{"published", signingRotation{Changed: true, KID: "new", Status: "next", Since: since, ActiveFrom: &from, Replaced: "old"},
			[]string{"published signing key new", "after 2026-09-26 08:30 UTC", "old keeps signing"}},
		{"already waiting", signingRotation{KID: "next", Status: "next", Since: since, ActiveFrom: &from, Replaced: "old"},
			[]string{"signing key next has been published since 2026-09-25 08:30 UTC", "nothing changed"}},
		{"revoked", signingRotation{Revoked: true, Changed: true, KID: "new", Status: "active", Since: since, Replaced: "old", Retired: []string{"a", "old"}},
			[]string{"signing key new is active", "retired a, old", "refused"}},
		{"first key", signingRotation{Changed: true, KID: "new", Status: "active", Since: since},
			[]string{"signing key new is active; there was no key before it"}},
	}
	for _, c := range cases {
		var text bytes.Buffer
		if err := writeSigningRotation(&text, c.r, "text"); err != nil {
			t.Fatal(err)
		}
		for _, w := range c.want {
			if !strings.Contains(text.String(), w) {
				t.Errorf("%s: %q lacks %q", c.name, text.String(), w)
			}
		}
		var asJSON bytes.Buffer
		if err := writeSigningRotation(&asJSON, c.r, "json"); err != nil {
			t.Fatal(err)
		}
		var back signingRotation
		if err := json.Unmarshal(asJSON.Bytes(), &back); err != nil {
			t.Fatalf("%s: the JSON does not parse: %v\n%s", c.name, err, asJSON.String())
		}
		if back.KID != c.r.KID || back.Status != c.r.Status || back.Revoked != c.r.Revoked || (back.ActiveFrom == nil) != (c.r.ActiveFrom == nil) {
			t.Errorf("%s: the JSON round trip changed the report: %+v", c.name, back)
		}
	}
}

// signingCmdTestDB is this test's own database. signing_keys is
// instance-wide, so a test that rotates it runs beside DATABASE_URL, not
// in it (see keysTestDB in internal/mcpauth).
const signingCmdTestDB = "supermcp_cmd_signing_tests"

// The command end to end: a revoke leaves one active key, and the audit
// trail says who did it and that it was a revoke.
func TestKeysRotateSigningRevokesAndAudits(t *testing.T) {
	base := os.Getenv("DATABASE_URL")
	if base == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	url := ownTestDatabase(ctx, t, base, signingCmdTestDB)
	t.Setenv("DATABASE_URL", url)
	t.Setenv("SUPERMCP_MAINT_DATABASE_URL", url)
	t.Setenv("SUPERMCP_KEK_PROVIDER", "local")
	// A fixed key: the instance data key it wraps outlives the run.
	t.Setenv("ENCRYPTION_KEK", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	t.Setenv("SUPERMCP_KEK_PREVIOUS", "")

	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err := conn.Exec(ctx, `DELETE FROM signing_keys`); err != nil {
		t.Fatal(err)
	}

	// On an empty table the first key is active at once; then the
	// scheduled shape, a next key beside it; then a run with nothing to do.
	for _, by := range []string{"first-run", "second-run", "third-run"} {
		if err := keysCmd([]string{"rotate-signing", "-by", by}); err != nil {
			t.Fatalf("%s: %v", by, err)
		}
	}
	if err := keysCmd([]string{"rotate-signing", "--revoke", "-by", "incident-7"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	var active, retired int
	if err := conn.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'active'), count(*) FILTER (WHERE status = 'retired') FROM signing_keys`).
		Scan(&active, &retired); err != nil {
		t.Fatal(err)
	}
	if active != 1 || retired != 2 {
		t.Fatalf("after the revoke: %d active, %d retired; wanted 1 and 2", active, retired)
	}

	var kid string
	if err := conn.QueryRow(ctx, `SELECT kid FROM signing_keys WHERE status = 'active'`).Scan(&kid); err != nil {
		t.Fatal(err)
	}
	var actor string
	var meta map[string]any
	if err := conn.QueryRow(ctx, `SELECT actor_display, meta FROM audit_events
		WHERE action = 'signing_key.rotate' AND target_id = $1`, kid).Scan(&actor, &meta); err != nil {
		t.Fatalf("no audit event for the revoke: %v", err)
	}
	if actor != "supermcp keys rotate-signing" || meta["by"] != "incident-7" || meta["revoked"] != true {
		t.Fatalf("the revoke was recorded as %q %v", actor, meta)
	}
	// The third run changed nothing and so recorded nothing.
	var runs int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM audit_events
		WHERE action = 'signing_key.rotate' AND meta->>'by' = 'third-run'`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 0 {
		t.Fatalf("a run that changed nothing wrote %d audit events", runs)
	}
}

// ownTestDatabase creates name beside the database base names, applies
// the schema, and returns its URL. It is left behind between runs, as
// the other packages' own databases are.
func ownTestDatabase(ctx context.Context, t *testing.T, base, name string) string {
	t.Helper()
	u, err := neturl.Parse(base)
	if err != nil {
		t.Fatalf("DATABASE_URL is not a URL: %v", err)
	}
	admin := *u
	admin.Path = "/postgres"
	conn, err := pgx.Connect(ctx, admin.String())
	if err != nil {
		t.Skipf("could not reach Postgres to make this test's own database: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := conn.Exec(ctx, `CREATE DATABASE `+name); err != nil && !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("could not create %s: %v", name, err)
		}
	}
	own := *u
	own.Path = "/" + name
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	st, err := store.Open(ctx, own.String(), own.String(), log, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx, true); err != nil {
		t.Fatalf("could not apply the schema to %s: %v", name, err)
	}
	return own.String()
}
