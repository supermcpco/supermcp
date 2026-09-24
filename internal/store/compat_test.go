package store_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/supermcpco/supermcp/internal/store"
)

// migrationsPath is where the migrations live inside the repository, as git
// spells it.
const migrationsPath = "internal/store/migrations"

// compatTimeout bounds the whole test: two databases created, migrated
// twice and dropped. Well clear of a slow run, short enough that a wedged
// advisory lock fails the build instead of hanging it.
const compatTimeout = 5 * time.Minute

// TestMigrationsFromPreviousRelease is the N-1 test. It applies the
// migrations as the previous release shipped them, then applies the
// current set on top, and asserts the schema ends up byte-identical to
// what a migration onto an empty database produces.
//
// What this catches is a migration written against a clean database: one
// that recreates a table instead of altering it, or re-grants on ALL
// TABLES and so silently widens a role, or edits an already-applied file
// so goose never runs the change at all. All three pass every other test
// in this repository and take an instance down during a rolling upgrade,
// because the instance being upgraded is never empty.
func TestMigrationsFromPreviousRelease(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), compatTimeout)
	defer cancel()
	ref := previousRef(ctx, t)

	old := migrationsAt(ctx, t, ref)
	if len(old) == 0 {
		t.Skipf("%s has no migrations under %s, so there is no previous schema to upgrade from", ref, migrationsPath)
	}
	current, err := store.LatestVersion()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("upgrading from %s (%d migrations) to the working tree (version %d)", ref, len(old), current)
	if added := addedSince(t, old); len(added) > 0 {
		t.Logf("migrations added since %s: %s", ref, strings.Join(added, ", "))
	}

	// Two databases, not one: the upgraded schema is only meaningful next
	// to the one a new installation would get today.
	upgraded := scratchDatabase(ctx, t, dsn, "up")
	fresh := scratchDatabase(ctx, t, dsn, "fresh")

	applyOld(ctx, t, upgraded, ref, old)
	migrate(ctx, t, upgraded)
	migrate(ctx, t, fresh)

	want := dumpSchema(ctx, t, fresh)
	got := dumpSchema(ctx, t, upgraded)
	if diff := firstDifference(want, got); diff != "" {
		t.Errorf("the upgraded schema is not the schema a fresh install gets\n%s", diff)
	}

	if a, b := schemaVersion(ctx, t, upgraded), schemaVersion(ctx, t, fresh); a != b {
		t.Errorf("upgraded stopped at version %d, fresh reached %d", a, b)
	}
}

// previousRef names the release the upgrade starts from. An operator can
// override it to rehearse an upgrade from any point in history, which is
// also how this test earns its keep before the first tag exists.
func previousRef(ctx context.Context, t *testing.T) string {
	t.Helper()
	if ref := os.Getenv("SUPERMCP_COMPAT_REF"); ref != "" {
		return ref
	}
	ref, err := git(ctx, t, "describe", "--tags", "--abbrev=0")
	if err != nil {
		t.Skip("no release tag to upgrade from; set SUPERMCP_COMPAT_REF to a ref (a tag, or something like HEAD~20) to rehearse one")
	}
	return ref
}

// migrationsAt returns the migration files as they were at ref, newest
// last. The list is computed from git rather than from a checked-in
// manifest, because a manifest is one more thing to forget to update.
func migrationsAt(ctx context.Context, t *testing.T, ref string) []string {
	t.Helper()
	out, err := git(ctx, t, "ls-tree", "--full-tree", "--name-only", ref, migrationsPath+"/")
	if err != nil {
		t.Skipf("%s is not a ref this checkout knows (a shallow clone will not have it): %v", ref, err)
	}
	var files []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasSuffix(line, ".sql") {
			files = append(files, line)
		}
	}
	return files
}

// addedSince names the migrations this working tree has and ref did not.
// It is only reported, never asserted: which files are new is the thing
// under test, not a fact to pin.
func addedSince(t *testing.T, old []string) []string {
	t.Helper()
	was := make(map[string]bool, len(old))
	for _, f := range old {
		was[filepath.Base(f)] = true
	}
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	var added []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") && !was[e.Name()] {
			added = append(added, e.Name())
		}
	}
	return added
}

// applyOld materialises the old migrations into a temporary directory and
// runs them. They are read out of git, so a file edited in the working
// tree is still applied here as the previous release shipped it, which is
// the whole point.
func applyOld(ctx context.Context, t *testing.T, dsn, ref string, files []string) {
	t.Helper()
	dir := t.TempDir()
	for _, f := range files {
		body, err := git(ctx, t, "show", ref+":"+strings.TrimSpace(f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(f)), []byte(body+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	st := open(ctx, t, dsn)
	db := stdlib.OpenDBFromPool(st.Maint)
	defer func() { _ = db.Close() }()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("apply the previous release's migrations: %v", err)
	}
}

// migrate runs the migrations compiled into this binary, the same call
// `supermcp migrate` makes.
func migrate(ctx context.Context, t *testing.T, dsn string) {
	t.Helper()
	if err := open(ctx, t, dsn).Migrate(ctx, true); err != nil {
		t.Fatalf("migrate %s: %v", redact(dsn), err)
	}
}

func open(ctx context.Context, t *testing.T, dsn string) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, dsn, dsn, slog.New(slog.NewTextHandler(io.Discard, nil)), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

func schemaVersion(ctx context.Context, t *testing.T, dsn string) int64 {
	t.Helper()
	v, err := open(ctx, t, dsn).SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// scratchDatabase creates an empty database beside the one DATABASE_URL
// points at, and drops it afterwards. The name carries the process id so
// two runs on one cluster cannot collide.
func scratchDatabase(ctx context.Context, t *testing.T, dsn, suffix string) string {
	t.Helper()
	name := fmt.Sprintf("supermcp_compat_%d_%s", os.Getpid(), suffix)
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately not ctx: a connection must close even when the caller's
	// context is already done.
	defer func() { //nolint:contextcheck
		_ = admin.Close(context.Background())
	}()

	// Dropped first in case a previous run was killed before its cleanup.
	if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+quoteIdent(name)); err != nil {
		t.Skipf("cannot create a scratch database (the test needs a role that may CREATE DATABASE): %v", err)
	}
	// Deliberately not the test's context: it may already be cancelled, and
	// a leaked database outlives the run.
	t.Cleanup(func() { //nolint:contextcheck
		dropCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(dropCtx, dsn)
		if err != nil {
			t.Logf("drop %s: %v", name, err)
			return
		}
		defer func() { _ = conn.Close(context.Background()) }()
		if _, err := conn.Exec(dropCtx, `DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`); err != nil {
			t.Logf("drop %s: %v", name, err)
		}
	})
	return replaceDatabase(t, dsn, name)
}

// schemaQueries are what "the same schema" means here. Between them they
// cover every object a migration in this repository creates, and each one
// is the shape of a real upgrade accident: a column that ends up nullable
// on one path, an index that only a fresh install gets, a policy that an
// upgraded instance keeps from its old definition, a grant that widens.
var schemaQueries = []string{
	`SELECT format('column %s.%s %s null=%s default=%s', table_name, column_name, data_type, is_nullable, coalesce(column_default, '-'))
	   FROM information_schema.columns WHERE table_schema = 'public'`,

	`SELECT format('constraint %s %s %s', conrelid::regclass, conname, pg_get_constraintdef(c.oid))
	   FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace WHERE n.nspname = 'public'`,

	`SELECT format('index %s %s', indexname, indexdef) FROM pg_indexes WHERE schemaname = 'public'`,

	`SELECT format('rls %s force=%s enabled=%s', relname, relforcerowsecurity, relrowsecurity)
	   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
	   WHERE n.nspname = 'public' AND c.relkind = 'r'`,

	`SELECT format('policy %s %s cmd=%s roles=%s using=%s check=%s', tablename, policyname, cmd,
	          array_to_string(roles, '+'), coalesce(qual, '-'), coalesce(with_check, '-'))
	   FROM pg_policies WHERE schemaname = 'public'`,

	`SELECT format('trigger %s %s', tgrelid::regclass, pg_get_triggerdef(t.oid))
	   FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
	   WHERE n.nspname = 'public' AND NOT t.tgisinternal`,

	// The body is hashed rather than compared: a function redefined with
	// different whitespace is the same function, and a function redefined
	// with different logic is not.
	`SELECT format('function %s(%s) %s %s', p.proname, pg_get_function_identity_arguments(p.oid),
	          p.prosecdef, md5(p.prosrc))
	   FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'`,

	`SELECT format('enum %s %s %s', t.typname, e.enumsortorder, e.enumlabel)
	   FROM pg_type t JOIN pg_enum e ON e.enumtypid = t.oid
	   JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public'`,

	`SELECT format('sequence %s %s', sequence_name, data_type) FROM information_schema.sequences WHERE sequence_schema = 'public'`,

	`SELECT format('grant %s %s %s', grantee, table_name, privilege_type)
	   FROM information_schema.role_table_grants WHERE table_schema = 'public' AND grantee = 'supermcp_app'`,

	`SELECT format('column-grant %s %s.%s %s', grantee, table_name, column_name, privilege_type)
	   FROM information_schema.column_privileges WHERE table_schema = 'public' AND grantee = 'supermcp_app'`,

	`SELECT format('default-privilege %s %s', pg_get_userbyid(defaclrole), array_to_string(defaclacl, '+'))
	   FROM pg_default_acl a JOIN pg_namespace n ON n.oid = a.defaclnamespace WHERE n.nspname = 'public'`,
}

// dumpSchema renders the schema as sorted lines, so a difference reads as
// a difference and not as a reordering.
func dumpSchema(ctx context.Context, t *testing.T, dsn string) []string {
	t.Helper()
	st := open(ctx, t, dsn)
	var out []string
	for _, q := range schemaQueries {
		rows, err := st.Maint.Query(ctx, q)
		if err != nil {
			t.Fatalf("schema query: %v", err)
		}
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			out = append(out, line)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(out)
	return out
}

// firstDifference reports what an operator needs to act on: the objects
// one schema has and the other does not, capped so a wholesale divergence
// does not bury the first real line.
func firstDifference(want, got []string) string {
	const maxLines = 20
	inGot := make(map[string]bool, len(got))
	for _, l := range got {
		inGot[l] = true
	}
	inWant := make(map[string]bool, len(want))
	for _, l := range want {
		inWant[l] = true
	}
	var b strings.Builder
	n := 0
	for _, l := range want {
		if !inGot[l] && n < maxLines {
			fmt.Fprintf(&b, "  only after a fresh migration: %s\n", l)
			n++
		}
	}
	for _, l := range got {
		if !inWant[l] && n < maxLines {
			fmt.Fprintf(&b, "  only after the upgrade:       %s\n", l)
			n++
		}
	}
	if n == maxLines {
		b.WriteString("  ... more differences suppressed\n")
	}
	return b.String()
}

// git runs one command in the repository this test lives in.
func git(ctx context.Context, t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(out), "\n"), nil
}

// replaceDatabase points a DSN at another database on the same cluster.
func replaceDatabase(t *testing.T, dsn, name string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("DATABASE_URL is not a URL: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

// redact keeps a password out of a failure message.
func redact(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "the database"
	}
	if u.User != nil {
		u.User = url.User(u.User.Username())
	}
	return u.String()
}

// quoteIdent quotes a database name for DDL. The names this test builds
// are its own, but a quoted identifier is the only correct way to write
// one and costs nothing.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
