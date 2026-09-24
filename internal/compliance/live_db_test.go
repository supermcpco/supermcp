// These tests run against a live Postgres, because every report in this
// package is a statement about rows, about the policies that decide which
// rows a connection can see, and about a hash chain none of which
// survives a fake. Set DATABASE_URL to run them.
package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// fixture is one test's workspace, and everything in it. The app pool is
// opened with the row-level-security role set, because half of what these
// reports claim is that they read what a request would read.
type fixture struct {
	t   *testing.T
	d   Deps
	log *slog.Logger

	org, slug            string
	alice, bob           string
	aliceEmail, bobEmail string
	stale, rotated       string // service accounts, one never rotated and one rotated
	now                  time.Time
	lo, hi               int64 // the seq range this test's audit events occupy
}

func newFixture(ctx context.Context, t *testing.T) *fixture {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set; these reports can only be tested against a live Postgres")
	}
	// The schema is applied first, as the maintenance role: a database
	// that has never been migrated has neither the tables these reports
	// read nor the row-level-security role the next pool asks for.
	maint, err := store.Open(ctx, url, url, testLog(), store.Options{})
	if err != nil {
		t.Fatalf("could not open DATABASE_URL: %v", err)
	}
	if err := maint.Migrate(ctx, true); err != nil {
		maint.Close()
		t.Fatalf("could not apply the schema: %v", err)
	}
	maint.Close()

	st, err := store.Open(ctx, url, url, testLog(), store.Options{AppRole: true})
	if err != nil {
		t.Fatalf("could not open the app and maintenance pools against DATABASE_URL: %v", err)
	}
	t.Cleanup(st.Close)

	safe := strings.NewReplacer("/", "_", " ", "_", "#", "_").Replace(t.Name())
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	f := &fixture{
		t:    t,
		log:  testLog(),
		org:  "cmpl_" + safe,
		slug: "cmpl-" + strings.ToLower(safe),
		now:  now,
	}
	f.d = Deps{DB: &tenant.DB{App: st.App, Maint: st.Maint, Log: f.log}, Now: now}
	f.alice, f.bob = f.org+"_alice", f.org+"_bob"
	f.aliceEmail = "alice." + strings.ToLower(safe) + "@example.test"
	f.bobEmail = "bob." + strings.ToLower(safe) + "@example.test"
	f.stale, f.rotated = f.org+"_sa_stale", f.org+"_sa_rotated"

	f.purge(ctx)
	t.Cleanup(func() { f.purge(context.WithoutCancel(ctx)) })
	f.seed(ctx)
	return f
}

func (f *fixture) exec(ctx context.Context, sql string, args ...any) int64 {
	f.t.Helper()
	var n int64
	err := f.d.DB.Bypass(ctx, "compliance test fixture", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, sql, args...)
		n = tag.RowsAffected()
		return err
	})
	if err != nil {
		f.t.Fatalf("fixture statement failed: %v\n%s", err, sql)
	}
	return n
}

func (f *fixture) purge(ctx context.Context) {
	f.t.Helper()
	// audit_events carries no foreign key to the workspace, so deleting the
	// workspace would leave this test's events behind to fail the next run.
	f.exec(ctx, `DELETE FROM audit_events WHERE organization_id = $1`, f.org)
	f.exec(ctx, `DELETE FROM tool_invocations WHERE organization_id = $1`, f.org)
	f.exec(ctx, `DELETE FROM organizations WHERE id = $1`, f.org)
	f.exec(ctx, `DELETE FROM users WHERE id = ANY($1)`, []string{f.alice, f.bob})
}

func (f *fixture) seed(ctx context.Context) {
	f.t.Helper()
	old := f.now.AddDate(0, 0, -200)
	recent := f.now.AddDate(0, 0, -2)

	f.exec(ctx, `INSERT INTO organizations (id, slug, name) VALUES ($1, $2, $3)`, f.org, f.slug, "Compliance test")
	f.exec(ctx, `INSERT INTO users (id, email, name, created_at) VALUES ($1, $2, $3, $4), ($5, $6, $7, $4)`,
		f.alice, f.aliceEmail, "Alice Example", old, f.bob, f.bobEmail, "Bob Example")
	f.exec(ctx, `INSERT INTO organization_members (user_id, organization_id, created_at) VALUES ($1, $3, $4), ($2, $3, $4)`,
		f.alice, f.bob, f.org, old)

	// Alice holds the owner role with no expiry, which is the finding a
	// real review is run to produce.
	f.exec(ctx, `INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id, scope_kind, source, created_at)
		VALUES ($1, $2, 'user', $3, 'role_owner', 'org', 'manual', $4)`, f.org+"_b1", f.org, f.alice, old)
	// And an expired one, which grants nothing and is still on the record.
	f.exec(ctx, `INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id, scope_kind, source, expires_at, created_at)
		VALUES ($1, $2, 'user', $3, 'role_auditor', 'org', 'manual', $4, $5)`,
		f.org+"_b2", f.org, f.alice, f.now.AddDate(0, 0, -1), old)
	// Bob is a member of the workspace and holds nothing at all.

	f.exec(ctx, `INSERT INTO service_accounts (id, organization_id, name, client_id, secret_prefix, created_at)
		VALUES ($1, $2, 'stale', $3, 'sa_st', $5), ($4, $2, 'rotated', $6, 'sa_ro', $5)`,
		f.stale, f.org, f.org+"_cid_stale", f.rotated, old, f.org+"_cid_rotated")
	f.exec(ctx, `INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id, scope_kind, source, created_at)
		VALUES ($1, $2, 'service_account', $3, 'role_mcp_consumer', 'org', 'manual', $4)`,
		f.org+"_b3", f.org, f.rotated, old)

	f.exec(ctx, `INSERT INTO api_keys (id, organization_id, principal_kind, principal_id, name, prefix, hash, scopes, created_at, last_used_at)
		VALUES ($1, $2, 'user', $3, 'alice laptop', $4, $5, ARRAY['mcp:tools:invoke'], $6, $7)`,
		f.org+"_k1", f.org, f.alice, f.org+"_pfx", []byte{1, 2, 3}, old, recent)

	f.exec(ctx, `INSERT INTO tool_invocations
		(id, organization_id, tool_name, principal_kind, principal_id, auth_method, status, duration_ms, input, created_at)
		VALUES ($1, $2, 'search', 'user', $3, 'session', 'success', 5, $4, $5)`,
		f.org+"_i1", f.org, f.alice, []byte(fmt.Sprintf(`{"q":%q}`, f.aliceEmail)), recent)

	f.exec(ctx, `INSERT INTO revisions (id, organization_id, entity_kind, entity_id, revision, snapshot, action, actor_id, actor_display, created_at)
		VALUES ($1, $2, 'connector', $3, 1, $4, 'create', $5, $6, $7)`,
		f.org+"_r1", f.org, f.org+"_c1", []byte(`{"name":"prod"}`), f.alice, f.aliceEmail, recent)

	f.seedAudit(ctx)
}

// seedAudit writes through the real writer, because the chain is built by
// it and a row inserted by hand would not verify.
func (f *fixture) seedAudit(ctx context.Context) {
	f.t.Helper()
	w := audit.NewWriter(f.d.DB, f.log, //nolint:contextcheck // the writer appends from its own goroutine
		audit.Options{Now: func() time.Time { return f.now }})
	defer w.Close()
	events := []audit.Event{
		{OrgID: f.org, Category: audit.CategoryAuth, Action: "session.create", Outcome: audit.Success,
			ActorKind: "user", ActorID: f.alice, ActorDisplay: f.aliceEmail},
		{OrgID: f.org, Category: audit.CategoryAdmin, Action: "member.update", Outcome: audit.Success,
			ActorKind: "user", ActorID: f.bob, ActorDisplay: f.bobEmail,
			TargetKind: "user", TargetID: f.alice, TargetDisplay: f.aliceEmail,
			// The diff records the address itself, which is what an erasure
			// cannot rewrite: the chain covers a digest of this column.
			Diff: audit.Changes(map[string]any{"email": "old." + f.aliceEmail}, map[string]any{"email": f.aliceEmail})},
		{OrgID: f.org, Category: audit.CategorySecrets, Action: "service_account.rotate_secret", Outcome: audit.Success,
			ActorKind: "user", ActorID: f.alice, ActorDisplay: f.aliceEmail,
			TargetKind: "service_account", TargetID: f.rotated},
	}
	for _, e := range events {
		if err := w.EmitSync(ctx, e); err != nil {
			f.t.Fatalf("seeding the audit stream failed, so nothing about the chain can be tested: %v", err)
		}
	}
	f.lo, f.hi = f.bounds(ctx)
}

func (f *fixture) bounds(ctx context.Context) (int64, int64) {
	f.t.Helper()
	var lo, hi *int64
	err := f.d.DB.Bypass(ctx, "compliance test bounds", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT min(seq), max(seq) FROM audit_events WHERE organization_id = $1`, f.org).Scan(&lo, &hi)
	})
	if err != nil || lo == nil || hi == nil {
		f.t.Fatalf("could not read back the seq range for %s: %v", f.org, err)
	}
	return *lo, *hi
}

// verify walks the stretch of chain this test's events live in. The whole
// instance shares one sequence, so a tenant's rows can only be trusted as
// far as the rows around them are; the range is what keeps one test from
// failing on another's leftovers.
func (f *fixture) verify(ctx context.Context) *audit.VerifyResult {
	f.t.Helper()
	r := &audit.Reader{DB: f.d.DB}
	res, err := r.Verify(ctx, f.lo, f.hi)
	if err != nil {
		f.t.Fatalf("verifying the chain failed outright: %v", err)
	}
	return res
}

func (f *fixture) principal(rev *Review, kind, id string) *Principal {
	f.t.Helper()
	for i := range rev.Workspaces {
		if rev.Workspaces[i].OrgID != f.org {
			continue
		}
		for j := range rev.Workspaces[i].Principals {
			p := &rev.Workspaces[i].Principals[j]
			if p.Kind == kind && p.ID == id {
				return p
			}
		}
	}
	f.t.Fatalf("the review has no %s %s; it covered %d workspaces", kind, id, len(rev.Workspaces))
	return nil
}

func hasFinding(p *Principal, code string) bool {
	for _, f := range p.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------

func TestAccessReviewReportsWhatAReviewerLooksFor(t *testing.T) {
	ctx := context.Background()
	f := newFixture(ctx, t)

	rev, err := AccessReview(ctx, f.d, AccessOptions{OrgID: f.org})
	if err != nil {
		t.Fatalf("the access review failed: %v", err)
	}
	if len(rev.Workspaces) != 1 {
		t.Fatalf("asking for one workspace returned %d", len(rev.Workspaces))
	}

	alice := f.principal(rev, "user", f.alice)
	switch {
	case !hasFinding(alice, FindingPrivilegedForever):
		t.Errorf("owner with no expiry was not flagged; findings were %v", alice.Findings)
	case !hasFinding(alice, FindingExpiredBinding):
		t.Errorf("the expired binding was not reported; findings were %v", alice.Findings)
	case len(alice.Effective) != 36:
		t.Errorf("the owner's effective set has %d permissions; the wildcard should expand to the whole closed set plus itself", len(alice.Effective))
	case alice.LastUsed == nil:
		t.Error("alice has an API key used two days ago and the review says she has never been used")
	}

	bob := f.principal(rev, "user", f.bob)
	if !hasFinding(bob, FindingNoBinding) {
		t.Errorf("a member holding no binding was not reported; findings were %v", bob.Findings)
	}
	if !hasFinding(bob, FindingNeverUsed) {
		t.Errorf("a member created 200 days ago and never used was not reported; findings were %v", bob.Findings)
	}

	stale := f.principal(rev, "service_account", f.stale)
	if !hasFinding(stale, FindingSecretNotRotated) {
		t.Errorf("a service account with no rotation in the stream was not reported; findings were %v", stale.Findings)
	}
	rotated := f.principal(rev, "service_account", f.rotated)
	if hasFinding(rotated, FindingSecretNotRotated) {
		t.Errorf("a service account whose rotation is in the stream was reported as never rotated")
	}

	key := f.principal(rev, "api_key", f.org+"_k1")
	if !hasFinding(key, FindingKeyNeverExpires) {
		t.Errorf("an API key with no expiry was not reported; findings were %v", key.Findings)
	}
	// The key carries mcp:tools:invoke and nothing else, so its owner's
	// thirty-six permissions come down to the three it can reach.
	if got := strings.Join(key.Effective, " "); got != "tools:read tools:invoke tools:invoke:destructive" {
		t.Errorf("a scoped key resolved to %q; a scoped credential cannot do more than read and invoke tools", got)
	}
}

func TestAccessReviewRendersInEveryFormat(t *testing.T) {
	ctx := context.Background()
	f := newFixture(ctx, t)
	rev, err := AccessReview(ctx, f.d, AccessOptions{OrgID: f.org})
	if err != nil {
		t.Fatalf("the access review failed: %v", err)
	}
	var text, jsonOut, csvOut strings.Builder
	for name, err := range map[string]error{
		"text": rev.WriteText(&text), "json": rev.WriteJSON(&jsonOut), "csv": rev.WriteCSV(&csvOut),
	} {
		if err != nil {
			t.Fatalf("rendering %s failed: %v", name, err)
		}
	}
	if !strings.Contains(text.String(), f.aliceEmail) {
		t.Error("the text report does not name the person it is about")
	}
	if !strings.Contains(text.String(), "What this report cannot see") {
		t.Error("the text report does not say what it cannot see, which is half of an honest report")
	}
	var parsed Review
	if err := json.Unmarshal([]byte(jsonOut.String()), &parsed); err != nil {
		t.Fatalf("the JSON report does not parse: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(csvOut.String()), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "workspace_slug,") {
		t.Fatalf("the CSV has no header or no rows: %q", csvOut.String())
	}
	// Bob holds no binding and still gets a row: "this person has no
	// access" is a thing a review has to state.
	if !strings.Contains(csvOut.String(), f.bobEmail) {
		t.Error("the CSV omits a principal with no bindings")
	}
}

func TestErasurePseudonymisesAndTheChainStillVerifies(t *testing.T) {
	ctx := context.Background()
	f := newFixture(ctx, t)

	if res := f.verify(ctx); !res.Valid {
		t.Fatalf("the chain was already broken before the erasure, at %d: %s", res.BrokenAt, res.Explained)
	}

	subject, err := FindSubject(ctx, f.d, f.aliceEmail)
	if err != nil {
		t.Fatalf("resolving the subject by email failed: %v", err)
	}
	if subject.UserID != f.alice {
		t.Fatalf("resolved %s, want %s", subject.UserID, f.alice)
	}

	res, err := Erase(ctx, f.d, subject, EraseOptions{})
	if err != nil {
		t.Fatalf("the erasure failed: %v", err)
	}

	after := f.verify(ctx)
	if !after.Valid {
		t.Fatalf("the erasure broke the audit chain at sequence %d: %s", after.BrokenAt, after.Explained)
	}
	if after.Checked == 0 {
		t.Fatal("the verification checked no rows, so it proved nothing")
	}

	changed := map[string]int64{}
	for _, c := range res.Changed {
		changed[c.Table] = c.Rows
	}
	switch {
	case changed["users"] != 1:
		t.Errorf("the account itself was rewritten in %d rows, want 1", changed["users"])
	case changed["audit_events"] != 3:
		t.Errorf("%d audit rows were pseudonymised; alice is the actor of two events and the target of one", changed["audit_events"])
	case changed["revisions"] != 1:
		t.Errorf("%d revisions were pseudonymised, want 1", changed["revisions"])
	}

	// The identity columns the chain covers must be exactly as they were.
	err = f.d.DB.Bypass(ctx, "compliance test assertions", func(tx pgx.Tx) error {
		var displays, ids int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_events
			WHERE organization_id = $1 AND (actor_display = $2 OR target_display = $2)`, f.org, f.aliceEmail).Scan(&displays); err != nil {
			return err
		}
		if displays != 0 {
			t.Errorf("%d audit rows still show the old address", displays)
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_events
			WHERE organization_id = $1 AND (actor_id = $2 OR target_id = $2)`, f.org, f.alice).Scan(&ids); err != nil {
			return err
		}
		if ids != 3 {
			t.Errorf("the actor and target ids changed: %d rows still name the account, want 3", ids)
		}
		var email, name string
		if err := tx.QueryRow(ctx, `SELECT email, name FROM users WHERE id = $1`, f.alice).Scan(&email, &name); err != nil {
			return err
		}
		if email != PseudonymAddress(f.alice) || name != Pseudonym(f.alice) {
			t.Errorf("the account reads %s / %s after the erasure", email, name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("reading back the erased rows failed: %v", err)
	}

	// The diff of the membership change still contains the address, and
	// the report has to say so rather than let anyone believe otherwise.
	var stated bool
	for _, u := range res.Untouched {
		if strings.Contains(u.Where, "diff") && u.Rows > 0 {
			stated = true
		}
	}
	if !stated {
		t.Errorf("the report does not say that an audit diff still holds the address: %+v", res.Untouched)
	}

	// Running it twice changes nothing, because the pseudonym is derived
	// from the account id and an already-erased row no longer matches.
	again, err := Erase(ctx, f.d, subject, EraseOptions{})
	if err != nil {
		t.Fatalf("the second erasure failed: %v", err)
	}
	for _, c := range again.Changed {
		if c.Rows != 0 {
			t.Errorf("a second erasure rewrote %d rows of %s; it should be a no-op", c.Rows, c.Table)
		}
	}
}

func TestExportHoldsTheSubjectsRecord(t *testing.T) {
	ctx := context.Background()
	f := newFixture(ctx, t)

	subject, err := FindSubject(ctx, f.d, f.alice)
	if err != nil {
		t.Fatalf("resolving the subject by id failed: %v", err)
	}
	ex, err := BuildExport(ctx, f.d, subject, ExportOptions{})
	if err != nil {
		t.Fatalf("building the export failed: %v", err)
	}

	byName := map[string]ExportFile{}
	for _, file := range ex.Files {
		byName[file.Name] = file
	}
	for name, want := range map[string]int{
		"memberships.json": 1, "role-bindings.json": 2, "api-keys.json": 1,
		"tool-calls.json": 1, "configuration-changes.json": 1, "audit-events.json": 3,
	} {
		got, ok := byName[name]
		if !ok {
			t.Errorf("the export has no %s", name)
			continue
		}
		if got.Records != want {
			t.Errorf("%s holds %d records, want %d", name, got.Records, want)
		}
	}
	// The one audit event Bob is the actor of names alice as its target,
	// so it belongs in her export; nothing that names only Bob does.
	if strings.Contains(string(byName["audit-events.json"].Bytes), f.bobEmail) {
		// Bob is the actor of the membership change, which is in alice's
		// export because she is its target. His address appearing there is
		// expected; his own events are not.
		t.Log("an event naming both people appears in the export, as the subject is its target")
	}
	if strings.Contains(string(byName["api-keys.json"].Bytes), "hash") {
		t.Error("the export mentions a key hash; credentials never leave, not even as digests")
	}

	dir := filepath.Join(t.TempDir(), "export")
	if _, err := ex.WriteTo(dir); err != nil {
		t.Fatalf("writing the export to a directory failed: %v", err)
	}
	for _, name := range []string{"manifest.json", "README.txt", "subject.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("the export is missing %s: %v", name, err)
		}
	}
	zipPath := filepath.Join(t.TempDir(), "export.zip")
	if _, err := ex.WriteTo(zipPath); err != nil {
		t.Fatalf("writing the export as a zip failed: %v", err)
	}
	if st, err := os.Stat(zipPath); err != nil || st.Size() == 0 {
		t.Fatalf("the zip is missing or empty: %v", err)
	}
	if _, err := os.Stat(zipPath + ".partial"); !os.IsNotExist(err) {
		t.Error("the partial file was left behind, so an interrupted run would look like a complete answer")
	}
}

func TestExportRefusesAnUnknownSubject(t *testing.T) {
	ctx := context.Background()
	f := newFixture(ctx, t)
	if _, err := FindSubject(ctx, f.d, "nobody@example.invalid"); err == nil {
		t.Fatal("an unknown address resolved to an account")
	}
}

func TestCryptoReportSaysWhatIsNotEncrypted(t *testing.T) {
	ctx := context.Background()
	f := newFixture(ctx, t)

	rep, err := CryptoReport(ctx, f.d, CryptoOptions{})
	if err != nil {
		t.Fatalf("the cryptography report failed: %v", err)
	}
	for _, k := range rep.DataKeys {
		if k.Opens != nil {
			t.Errorf("a run with no master key claimed to know whether key %s opens", k.ID)
		}
	}
	if rep.MasterKeys.Checked {
		t.Error("a run with no master key says it checked")
	}
	var text strings.Builder
	if err := rep.WriteText(&text); err != nil {
		t.Fatalf("rendering the report failed: %v", err)
	}
	for _, want := range []string{"What is NOT encrypted", "the database as a whole", "tool-call arguments and results"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("the report does not say %q, which is the half an assessor is owed", want)
		}
	}
	// The sealed columns come from the schema, so the ones this release
	// has must be there whether or not anything has been sealed yet.
	found := map[string]bool{}
	for _, s := range rep.Sealed {
		found[s.Table+"."+s.Column] = true
	}
	for _, want := range []string{"connector_credentials.value_enc", "signing_keys.private_enc", "approval_requests.args_enc"} {
		if !found[want] {
			t.Errorf("the report does not list %s as a sealed column", want)
		}
	}
}

func TestConfigSnapshotDescribesTheInstanceWithoutHandingItOver(t *testing.T) {
	ctx := context.Background()
	f := newFixture(ctx, t)

	snap, err := ConfigSnapshot(ctx, f.d, SnapshotOptions{
		Environ: []string{
			"DATABASE_URL=postgres://u:s3cret@db:5432/supermcp?sslmode=require",
			"ENCRYPTION_KEK=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			"SUPERMCP_LOG_LEVEL=info",
			"SUPERMCP_KMS_KEYID=typo",
			"PATH=/usr/bin",
		},
	})
	if err != nil {
		t.Fatalf("the snapshot failed: %v", err)
	}
	var text strings.Builder
	if err := snap.WriteText(&text); err != nil {
		t.Fatalf("rendering the snapshot failed: %v", err)
	}
	got := text.String()
	switch {
	case strings.Contains(got, "s3cret"):
		t.Error("the snapshot prints a database password")
	case strings.Contains(got, "AAAAAAAAAAAA"):
		t.Error("the snapshot prints the master key")
	case !strings.Contains(got, "sslmode=require"):
		t.Error("the snapshot hides whether the database connection is encrypted")
	case !strings.Contains(got, "PATH"):
		// PATH is not a setting of this system and is deliberately absent.
	case strings.Contains(got, "/usr/bin"):
		t.Error("the snapshot prints the whole environment, not only this system's settings")
	}
	// A variable that looks like one of this system's and is not read is
	// the misconfiguration worth catching.
	var flagged bool
	for _, s := range snap.Environment {
		if s.Name == "SUPERMCP_KMS_KEYID" && strings.Contains(s.Note, "does not read") {
			flagged = true
		}
	}
	if !flagged {
		t.Error("a SUPERMCP_ variable this binary does not read was not flagged; a setting that looks applied and is not is the expensive kind")
	}
	if snap.Instance.SchemaVersion == 0 {
		t.Error("the snapshot reports no schema version, so it cannot say whether the binary and the database agree")
	}
	var counted bool
	for _, c := range snap.Counts {
		if c.Of == "workspaces" && c.N > 0 {
			counted = true
		}
	}
	if !counted {
		t.Error("the snapshot counts no workspaces")
	}
}
