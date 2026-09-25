package rotatepg_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	neturl "net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/secrets/rotatepg"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
	"github.com/supermcpco/supermcp/internal/testdb"
)

// The tests in this file need a migrated database and are skipped without
// DATABASE_URL. They run against a database of this package's own, beside
// the one DATABASE_URL names: rotating the instance scope re-seals the
// signing keys under a key only this file's master key opens, which is
// exactly what a rotation is for and exactly what nobody else's tests can
// survive. The schema is the repository's own migrations, which is what
// CI deploys, so the catalogue is still checked against a real schema
// rather than against itself. The name carries this checkout's suffix
// (internal/testdb) so two worktrees never rotate each other's keys.
var rotateTestDB = testdb.Name("supermcp_rotate_tests")

func testDB(t *testing.T) (*tenant.DB, *pgxpool.Pool) {
	t.Helper()
	url := ownDatabase(t)
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(pool.Close)
	// Both pools are the maintenance role: rotation never uses the app
	// role, and neither does anything here.
	return &tenant.DB{App: pool, Maint: pool, Log: slog.New(slog.DiscardHandler)}, pool
}

// ownDatabase creates this package's database if it is not there,
// migrates it, and returns its URL.
func ownDatabase(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
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
	if err := conn.QueryRow(ctx, `SELECT true FROM pg_database WHERE datname = $1`, rotateTestDB).Scan(&exists); err != nil {
		// CREATE DATABASE cannot run inside a transaction, and two runs
		// race: whoever loses sees "already exists", which is fine.
		if _, err := conn.Exec(ctx, `CREATE DATABASE `+rotateTestDB); err != nil &&
			!strings.Contains(err.Error(), "already exists") {
			t.Fatalf("could not create %s: %v", rotateTestDB, err)
		}
	}
	own := *u
	own.Path = "/" + rotateTestDB
	st, err := store.Open(ctx, own.String(), own.String(), slog.New(slog.DiscardHandler), store.Options{})
	if err != nil {
		t.Fatalf("open %s: %v", rotateTestDB, err)
	}
	defer st.Close()
	if err := st.Migrate(ctx, true); err != nil {
		t.Fatalf("migrate %s: %v", rotateTestDB, err)
	}
	return own.String()
}

// testKEK is this file's master key. It is the same on every run so a
// second run can open what the first one sealed.
func testKEK(t *testing.T) secrets.KEK {
	t.Helper()
	k, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{23}, 32)), "rotatepg-test")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func exec(t *testing.T, db *tenant.DB, sql string, args ...any) {
	t.Helper()
	err := db.Bypass(context.Background(), "rotatepg-test", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, args...)
		return err
	})
	if err != nil {
		t.Fatalf("%s: %v", strings.SplitN(strings.TrimSpace(sql), "\n", 2)[0], err)
	}
}

func countRows(t *testing.T, db *tenant.DB, table string) int {
	t.Helper()
	var n int
	err := db.Bypass(context.Background(), "rotatepg-test", func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n)
	})
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// seeded is one row this test sealed, and what it has to still say
// afterwards.
type seeded struct {
	target secrets.ReSealTarget
	cursor string
	plain  string
}

func (s seeded) aad(orgID string) secrets.AAD {
	return secrets.AAD{Table: s.target.Table, Column: s.target.Column, RowID: s.cursor, OrgID: orgID}
}

// readSealed fetches one row's sealed column by the same expression the
// rotation addresses it with.
func readSealed(t *testing.T, db *tenant.DB, tg rotatepg.Target, cursor string) []byte {
	t.Helper()
	var v []byte
	q := fmt.Sprintf("SELECT %s FROM %s WHERE %s = $1", tg.Column, tg.Table, tg.IDColumn)
	err := db.Bypass(context.Background(), "rotatepg-test", func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), q, cursor).Scan(&v)
	})
	if err != nil {
		t.Fatalf("read %s row %q: %v", tg, cursor, err)
	}
	return v
}

func targetNamed(t *testing.T, table string) rotatepg.Target {
	t.Helper()
	for _, tg := range rotatepg.Targets {
		if tg.Table == table {
			return tg
		}
	}
	t.Fatalf("no rotation target for %s", table)
	return rotatepg.Target{}
}

// TestRotateEverySealedColumn seals a value in every column an
// organisation owns, rotates the workspace's data key, and requires all of
// them to open afterwards under the new key with the superseded one
// retired. It is the test the whole command exists to pass: a rotation
// that leaves one of these rows unopenable has destroyed a credential.
func TestRotateEverySealedColumn(t *testing.T) {
	db, _ := testDB(t)
	ctx := context.Background()
	kek := testKEK(t)
	keys := &store.KeyStore{DB: db}
	sealer := secrets.New(kek, keys)

	orgID := fmt.Sprintf("dekrot%d", time.Now().UnixNano())
	scope := secrets.ScopeOrg(orgID)
	connID := orgID + "-conn"
	t.Cleanup(func() {
		exec(t, db, `DELETE FROM organizations WHERE id = $1`, orgID)
		exec(t, db, `DELETE FROM data_keys WHERE scope = $1`, scope)
	})

	exec(t, db, `INSERT INTO organizations (id, slug, name) VALUES ($1,$1,$1)`, orgID)
	exec(t, db, `INSERT INTO connectors (id, organization_id, name, transport, auth) VALUES ($1,$2,'c','{}','{}')`, connID, orgID)

	// One row in every column this organisation owns, including two
	// credentials so the composite binding is exercised with more than one
	// name under the same connector.
	rows := []seeded{
		{targetNamed(t, "connector_credentials").ReSealTarget, connID + "/token", "credential-token"},
		{targetNamed(t, "connector_credentials").ReSealTarget, connID + "/password", "credential-password"},
		{targetNamed(t, "connector_tokens").ReSealTarget, connID, `{"access_token":"upstream"}`},
		{targetNamed(t, "identity_providers").ReSealTarget, orgID + "-idp", "oidc-client-secret"},
		{targetNamed(t, "audit_exporters").ReSealTarget, orgID + "-exp", `{"url":"https://example.test","secret":"shh"}`},
		{targetNamed(t, "approval_requests").ReSealTarget, orgID + "-apr", `{"amount":4200}`},
	}
	sealed := map[string][]byte{}
	for _, r := range rows {
		ct, err := sealer.Seal(ctx, scope, []byte(r.plain), r.aad(orgID))
		if err != nil {
			t.Fatalf("seal %s %q: %v", r.target, r.cursor, err)
		}
		sealed[r.target.String()+"|"+r.cursor] = ct
	}
	get := func(target, cursor string) []byte { return sealed[target+"|"+cursor] }

	exec(t, db, `INSERT INTO connector_credentials (connector_id, organization_id, name, value_enc) VALUES ($1,$2,'token',$3), ($1,$2,'password',$4)`,
		connID, orgID, get("connector_credentials.value_enc", connID+"/token"), get("connector_credentials.value_enc", connID+"/password"))
	exec(t, db, `INSERT INTO connector_tokens (connector_id, organization_id, token_enc, expires_at) VALUES ($1,$2,$3, now() + interval '1 day')`,
		connID, orgID, get("connector_tokens.token_enc", connID))
	exec(t, db, `INSERT INTO identity_providers (id, organization_id, name, preset, client_id, client_secret_enc) VALUES ($1,$2,'idp','generic','cid',$3)`,
		orgID+"-idp", orgID, get("identity_providers.client_secret_enc", orgID+"-idp"))
	// A public client has no secret. The column is nullable and a rotation
	// that treated an absent value as a malformed one would abandon the
	// whole run over a row with nothing in it.
	exec(t, db, `INSERT INTO identity_providers (id, organization_id, name, preset, client_id) VALUES ($1,$2,'public','generic','cid2')`,
		orgID+"-idp-public", orgID)
	exec(t, db, `INSERT INTO audit_exporters (id, organization_id, kind, config_enc) VALUES ($1,$2,'webhook',$3)`,
		orgID+"-exp", orgID, get("audit_exporters.config_enc", orgID+"-exp"))
	exec(t, db, `INSERT INTO approval_requests (id, organization_id, tool_id, tool_name, requested_by, args_enc, expires_at)
		VALUES ($1,$2,'t','tool','someone',$3, now() + interval '1 hour')`,
		orgID+"-apr", orgID, get("approval_requests.args_enc", orgID+"-apr"))

	before, ok, err := keys.Active(ctx, scope)
	if err != nil || !ok {
		t.Fatalf("active key before rotation: %v", err)
	}

	rowStore, err := rotatepg.NewStore(db, scope)
	if err != nil {
		t.Fatal(err)
	}
	deployed, err := rotatepg.Check(ctx, db)
	if err != nil {
		t.Fatalf("the rotation catalogue no longer matches the schema:\n%v", err)
	}
	targets := rotatepg.ScopeTargets(deployed, scope)
	if len(targets) < 5 {
		t.Fatalf("an organisation owns %d sealed columns, want at least the 5 seeded here", len(targets))
	}

	// Batch of two against three credentials, so the walk has to page.
	rep, err := secrets.RotateDataKey(ctx, secrets.DataKeyRotation{
		Store: keys, Sealer: sealer, Rows: rowStore, Scope: scope, Targets: targets, Batch: 2,
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rep.OldKeyID != before.ID {
		t.Errorf("rotation moved off key %x, want %x", rep.OldKeyID[:4], before.ID[:4])
	}
	if rep.OldKeyID == rep.NewKeyID {
		t.Fatal("the workspace kept the same data key")
	}
	if rep.ReSealed != len(rows) {
		t.Errorf("re-sealed %d rows, want %d", rep.ReSealed, len(rows))
	}
	if len(rep.Targets) != len(targets) {
		t.Errorf("report covers %d tables, want %d", len(rep.Targets), len(targets))
	}
	for _, tr := range rep.Targets {
		if tr.Vanished != 0 {
			t.Errorf("%s reported %d rows that went away", tr.Target, tr.Vanished)
		}
		if tr.Target == "identity_providers.client_secret_enc" && tr.Empty != 1 {
			t.Errorf("%s counted %d empty rows, want the one public client", tr.Target, tr.Empty)
		}
	}

	// Every value opens, says what it said, and sits on the new key. A
	// sealer built from scratch, so nothing is proved by a cached key.
	fresh := secrets.New(kek, &store.KeyStore{DB: db})
	for _, r := range rows {
		tg := targetNamed(t, r.target.Table)
		got := readSealed(t, db, tg, r.cursor)
		id, err := secrets.KeyID(got)
		if err != nil {
			t.Errorf("%s row %q: %v", r.target, r.cursor, err)
			continue
		}
		if id != rep.NewKeyID {
			t.Errorf("%s row %q is on key %x, want the new key %x", r.target, r.cursor, id[:4], rep.NewKeyID[:4])
		}
		pt, err := fresh.Open(ctx, got, r.aad(orgID))
		if err != nil {
			t.Errorf("%s row %q does not open after rotation: %v", r.target, r.cursor, err)
			continue
		}
		if string(pt) != r.plain {
			t.Errorf("%s row %q opened to %q, want %q", r.target, r.cursor, pt, r.plain)
		}
	}
	// The public client still has no secret; a rotation must not invent one.
	if v := readSealed(t, db, targetNamed(t, "identity_providers"), orgID+"-idp-public"); v != nil {
		t.Errorf("the provider with no secret gained %d bytes", len(v))
	}

	// Nothing references the old key, so it should have been let go.
	ret, err := secrets.RetireSuperseded(ctx, secrets.Retirement{
		Store: keys, Census: rowStore, Scope: scope, Targets: targets,
	})
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if len(ret.Held) != 0 {
		t.Errorf("keys held back: %v", ret.Held)
	}
	if got := keyStatus(t, db, rep.OldKeyID); got != "retired" {
		t.Errorf("the superseded key is %q, want retired", got)
	}
	if got := keyStatus(t, db, rep.NewKeyID); got != "active" {
		t.Errorf("the new key is %q, want active", got)
	}

	// Running again finds nothing left to move, which is what makes the
	// command safe to re-run after an interruption.
	again, err := secrets.RotateDataKey(ctx, secrets.DataKeyRotation{
		Store: keys, Sealer: sealer, Rows: rowStore, Scope: scope, Targets: targets, Batch: 2, ReSealOnly: true,
	})
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if again.ReSealed != 0 {
		t.Errorf("second pass re-sealed %d rows, want none", again.ReSealed)
	}
	if again.Scanned != 1 {
		// Only the null row keeps coming back: the narrowing query filters
		// out everything already on the active key.
		t.Errorf("second pass scanned %d rows, want only the one with nothing in it", again.Scanned)
	}
}

// TestRotateInstanceScope covers the one column sealed under the instance
// key rather than a workspace's. It is a separate scope with a separate
// key, and a rotation that quietly treated it as an organisation's would
// leave every signing key behind.
func TestRotateInstanceScope(t *testing.T) {
	db, _ := testDB(t)
	ctx := context.Background()
	kek := testKEK(t)
	keys := &store.KeyStore{DB: db}
	sealer := secrets.New(kek, keys)

	if n := countRows(t, db, "signing_keys"); n != 0 {
		t.Skipf("signing_keys already holds %d rows sealed by another master key; this test takes the instance scope over and will not do that to real data", n)
	}
	deployed, err := rotatepg.Check(ctx, db)
	if err != nil {
		t.Fatalf("the rotation catalogue no longer matches the schema:\n%v", err)
	}
	targets := rotatepg.ScopeTargets(deployed, secrets.ScopeInstance)
	if len(targets) != 1 || targets[0].Table != "signing_keys" {
		t.Fatalf("the instance scope owns %v, want signing_keys alone", targets)
	}
	rowStore, err := rotatepg.NewStore(db, secrets.ScopeInstance)
	if err != nil {
		t.Fatal(err)
	}

	// A scope has no key until something is sealed under it, and a fresh
	// database has sealed nothing. Minting one here also means the key
	// being superseded below is one this test can open.
	if _, err := sealer.Seal(ctx, secrets.ScopeInstance, []byte("mint the scope"), secrets.AAD{
		Table: "signing_keys", Column: "private_enc", RowID: "mint"}); err != nil {
		t.Fatalf("mint the instance key: %v", err)
	}

	// Take the scope over first. With no rows on it the outgoing key is
	// never unwrapped, so this works whatever master key wrapped the key
	// this installation happens to have started with, and what it leaves
	// behind is a key this test can open.
	if _, err := secrets.RotateDataKey(ctx, secrets.DataKeyRotation{
		Store: keys, Sealer: sealer, Rows: rowStore, Scope: secrets.ScopeInstance, Targets: targets,
	}); err != nil {
		t.Fatalf("take over the instance scope: %v", err)
	}

	kid := fmt.Sprintf("dekrot%d", time.Now().UnixNano())
	t.Cleanup(func() {
		exec(t, db, `DELETE FROM signing_keys WHERE kid = $1`, kid)
		// The instance scope cannot be handed back the key it had, so the
		// keys this test minted are tidied instead: the retired ones have
		// nothing on them by definition, and leaving them would make
		// `keys verify` report a growing pile of keys wrapped by a master
		// key only this file holds.
		exec(t, db, `DELETE FROM data_keys WHERE scope = $1 AND status = 'retired' AND kek_ref = $2`,
			secrets.ScopeInstance, testKEK(t).Ref())
	})
	aad := secrets.AAD{Table: "signing_keys", Column: "private_enc", RowID: kid}
	ct, err := sealer.Seal(ctx, secrets.ScopeInstance, []byte("private-key-der"), aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	exec(t, db, `INSERT INTO signing_keys (kid, alg, public_jwk, private_enc, status) VALUES ($1,'ES256','{}',$2,'active')`, kid, ct)

	rep, err := secrets.RotateDataKey(ctx, secrets.DataKeyRotation{
		Store: keys, Sealer: sealer, Rows: rowStore, Scope: secrets.ScopeInstance, Targets: targets,
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rep.ReSealed != 1 {
		t.Fatalf("re-sealed %d signing keys, want 1", rep.ReSealed)
	}
	got := readSealed(t, db, targetNamed(t, "signing_keys"), kid)
	// The binding carries no organisation, and a rotation that supplied
	// one would seal the row to a name the keyring never builds.
	pt, err := secrets.New(kek, &store.KeyStore{DB: db}).Open(ctx, got, aad)
	if err != nil || string(pt) != "private-key-der" {
		t.Fatalf("signing key does not open after rotation: %q %v", pt, err)
	}
	if _, err := secrets.RetireSuperseded(ctx, secrets.Retirement{
		Store: keys, Census: rowStore, Scope: secrets.ScopeInstance, Targets: targets,
	}); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if got := keyStatus(t, db, rep.OldKeyID); got != "retired" {
		t.Errorf("the superseded instance key is %q, want retired", got)
	}
}

// TestRetirementHoldsAKeyStillInUse is the other half of retirement: a key
// one row still names must stay decrypt-only, because retiring it would
// say the installation is finished with something it is not.
func TestRetirementHoldsAKeyStillInUse(t *testing.T) {
	db, _ := testDB(t)
	ctx := context.Background()
	kek := testKEK(t)
	keys := &store.KeyStore{DB: db}
	sealer := secrets.New(kek, keys)

	orgID := fmt.Sprintf("dekheld%d", time.Now().UnixNano())
	scope := secrets.ScopeOrg(orgID)
	connID := orgID + "-conn"
	t.Cleanup(func() {
		exec(t, db, `DELETE FROM organizations WHERE id = $1`, orgID)
		exec(t, db, `DELETE FROM data_keys WHERE scope = $1`, scope)
	})
	exec(t, db, `INSERT INTO organizations (id, slug, name) VALUES ($1,$1,$1)`, orgID)
	exec(t, db, `INSERT INTO connectors (id, organization_id, name, transport, auth) VALUES ($1,$2,'c','{}','{}')`, connID, orgID)
	aad := secrets.AAD{Table: "connector_credentials", Column: "value_enc", RowID: connID + "/token", OrgID: orgID}
	ct, err := sealer.Seal(ctx, scope, []byte("value"), aad)
	if err != nil {
		t.Fatal(err)
	}
	exec(t, db, `INSERT INTO connector_credentials (connector_id, organization_id, name, value_enc) VALUES ($1,$2,'token',$3)`, connID, orgID, ct)

	old, _, err := keys.Active(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	rowStore, err := rotatepg.NewStore(db, scope)
	if err != nil {
		t.Fatal(err)
	}
	// Demote the key and mint a replacement without moving the row, which
	// is what an interrupted rotation leaves behind.
	if err := keys.SetDataKeyStatus(ctx, old.ID, "decrypt_only"); err != nil {
		t.Fatal(err)
	}
	if _, err := sealer.Seal(ctx, scope, []byte("x"), secrets.AAD{OrgID: orgID}); err != nil {
		t.Fatal(err)
	}

	deployed, err := rotatepg.Check(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	ret, err := secrets.RetireSuperseded(ctx, secrets.Retirement{
		Store: keys, Census: rowStore, Scope: scope, Targets: rotatepg.ScopeTargets(deployed, scope),
	})
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if len(ret.Retired) != 0 {
		t.Errorf("retired %v while a row still used one of them", ret.Retired)
	}
	if n := ret.Held[fmt.Sprintf("%x", old.ID[:4])]; n != 1 {
		t.Errorf("held count = %d, want the one credential", n)
	}
	if got := keyStatus(t, db, old.ID); got != "decrypt_only" {
		t.Errorf("the key is %q, want it kept decrypt_only", got)
	}

	// Finishing the interrupted rotation moves the row forward onto the
	// key already minted, without minting another, and only then does the
	// superseded key become retirable. This is the whole resume story: the
	// command works the same state out for itself from the same census.
	targets := rotatepg.ScopeTargets(deployed, scope)
	fin, err := secrets.RotateDataKey(ctx, secrets.DataKeyRotation{
		Store: keys, Sealer: sealer, Rows: rowStore, Scope: scope, Targets: targets, ReSealOnly: true,
	})
	if err != nil {
		t.Fatalf("finish the interrupted rotation: %v", err)
	}
	if fin.ReSealed != 1 {
		t.Errorf("the resume moved %d rows, want the one left behind", fin.ReSealed)
	}
	if fin.OldKeyID != fin.NewKeyID {
		t.Errorf("the resume minted another key (%x -> %x)", fin.OldKeyID[:4], fin.NewKeyID[:4])
	}
	pt, err := secrets.New(kek, &store.KeyStore{DB: db}).Open(ctx,
		readSealed(t, db, targetNamed(t, "connector_credentials"), connID+"/token"), aad)
	if err != nil || string(pt) != "value" {
		t.Fatalf("the credential does not open after the resume: %q %v", pt, err)
	}
	ret, err = secrets.RetireSuperseded(ctx, secrets.Retirement{
		Store: keys, Census: rowStore, Scope: scope, Targets: targets,
	})
	if err != nil {
		t.Fatalf("retire after the resume: %v", err)
	}
	if len(ret.Retired) != 1 || len(ret.Held) != 0 {
		t.Errorf("after the resume: retired %v, held %v", ret.Retired, ret.Held)
	}
}

// TestWriteRefusesAnAmbiguousCursor is the guard against the one way a
// rotation can destroy a secret rather than merely fail to move it.
//
// A connector credential is addressed by "<connector id>/<name>", which is
// also its binding. Two rows can collide on that string when a connector
// id contains a slash — connector "a/b" credential "c" and connector "a"
// credential "b/c" are different rows with the same cursor. Writing either
// one by cursor would then bind a ciphertext to the other's name, leaving
// a credential nothing can open with its only plaintext gone. The write
// must refuse, by name, before the transaction commits.
func TestWriteRefusesAnAmbiguousCursor(t *testing.T) {
	db, _ := testDB(t)
	ctx := context.Background()
	kek := testKEK(t)
	keys := &store.KeyStore{DB: db}
	sealer := secrets.New(kek, keys)

	orgID := fmt.Sprintf("dekamb%d", time.Now().UnixNano())
	scope := secrets.ScopeOrg(orgID)
	t.Cleanup(func() {
		exec(t, db, `DELETE FROM organizations WHERE id = $1`, orgID)
		exec(t, db, `DELETE FROM data_keys WHERE scope = $1`, scope)
	})
	exec(t, db, `INSERT INTO organizations (id, slug, name) VALUES ($1,$1,$1)`, orgID)
	outer, inner := orgID+"/x", orgID
	exec(t, db, `INSERT INTO connectors (id, organization_id, name, transport, auth) VALUES ($1,$3,'a','{}','{}'), ($2,$3,'b','{}','{}')`,
		outer, inner, orgID)

	// Both rows share the cursor "<orgID>/x/y".
	cursor := orgID + "/x/y"
	aad := secrets.AAD{Table: "connector_credentials", Column: "value_enc", RowID: cursor, OrgID: orgID}
	ct, err := sealer.Seal(ctx, scope, []byte("v"), aad)
	if err != nil {
		t.Fatal(err)
	}
	exec(t, db, `INSERT INTO connector_credentials (connector_id, organization_id, name, value_enc) VALUES ($1,$3,'y',$4), ($2,$3,'x/y',$4)`,
		outer, inner, orgID, ct)

	rowStore, err := rotatepg.NewStore(db, scope)
	if err != nil {
		t.Fatal(err)
	}
	tg := targetNamed(t, "connector_credentials").ReSealTarget
	n, err := rowStore.WriteSealed(ctx, tg, []secrets.SealedRow{{Cursor: cursor, AAD: aad, Value: ct}})
	if err == nil {
		t.Fatalf("a write matching two rows was accepted (%d rows)", n)
	}
	if !strings.Contains(err.Error(), cursor) {
		t.Fatalf("the refusal does not name the row: %v", err)
	}
}

// TestCheckNamesASealedColumnNobodyRotates plants a sealed column the
// catalogue has never heard of and requires the pre-flight to refuse by
// name. This is the guard that lets this package hold a list of tables at
// all: without it, the next feature to seal a column would be rotated
// around in silence.
func TestCheckNamesASealedColumnNobodyRotates(t *testing.T) {
	db, _ := testDB(t)
	ctx := context.Background()
	table := fmt.Sprintf("dekprobe%d", time.Now().UnixNano())
	exec(t, db, fmt.Sprintf(`CREATE TABLE %s (id text PRIMARY KEY, mystery_enc bytea)`, table))
	t.Cleanup(func() { exec(t, db, fmt.Sprintf(`DROP TABLE IF EXISTS %s`, table)) })

	_, err := rotatepg.Check(ctx, db)
	if err == nil {
		t.Fatal("a sealed column no target names was not refused")
	}
	if !strings.Contains(err.Error(), table+".mystery_enc") {
		t.Fatalf("the refusal does not name the column: %v", err)
	}
}

// TestCheckPassesAgainstTheDeployedSchema is the live canary. When it
// fails, a sealed column has been added and rotatepg.Targets has not been
// told about it; the error says which one.
func TestCheckPassesAgainstTheDeployedSchema(t *testing.T) {
	db, _ := testDB(t)
	if _, err := rotatepg.Check(context.Background(), db); err != nil {
		t.Fatalf("the rotation catalogue no longer matches the schema:\n%v", err)
	}
}

func TestScopeTargetsSplitsTheScopes(t *testing.T) {
	t.Parallel()
	org := rotatepg.ScopeTargets(rotatepg.Targets, secrets.ScopeOrg("anything"))
	instance := rotatepg.ScopeTargets(rotatepg.Targets, secrets.ScopeInstance)
	if len(org)+len(instance) != len(rotatepg.Targets) {
		t.Fatalf("%d + %d targets, want all %d", len(org), len(instance), len(rotatepg.Targets))
	}
	for _, tg := range instance {
		for _, o := range org {
			if tg.String() == o.String() {
				t.Errorf("%s belongs to both scopes", tg)
			}
		}
	}
	for _, tg := range rotatepg.Targets {
		if tg.Table == "" || tg.Column == "" || tg.IDColumn == "" {
			t.Errorf("target %+v is incomplete", tg)
		}
	}
}

func TestOrgOfRefusesAScopeItDoesNotKnow(t *testing.T) {
	t.Parallel()
	if org, err := rotatepg.OrgOf(secrets.ScopeOrg("o1")); err != nil || org != "o1" {
		t.Errorf("OrgOf(org:o1) = %q, %v", org, err)
	}
	if org, err := rotatepg.OrgOf(secrets.ScopeInstance); err != nil || org != "" {
		t.Errorf("OrgOf(instance) = %q, %v", org, err)
	}
	for _, bad := range []string{"", "org:", "nonsense", "user:1"} {
		if _, err := rotatepg.OrgOf(bad); err == nil {
			t.Errorf("OrgOf(%q) was accepted", bad)
		}
	}
}

func keyStatus(t *testing.T, db *tenant.DB, id [16]byte) string {
	t.Helper()
	var status string
	err := db.Bypass(context.Background(), "rotatepg-test", func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT status FROM data_keys WHERE id = $1`, id[:]).Scan(&status)
	})
	if err != nil {
		t.Fatalf("read status of key %x: %v", id[:4], err)
	}
	return status
}
