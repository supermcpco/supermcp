package dlp_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/dlp"
	"github.com/supermcpco/supermcp/internal/governance"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// openTenantDB migrates DATABASE_URL and returns the app-role handle, the
// one row-level security applies to.
func openTenantDB(t *testing.T) *tenant.DB {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := t.Context()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	maint, err := store.Open(ctx, url, url, log, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := maint.Migrate(ctx, true); err != nil {
		t.Fatal(err)
	}
	maint.Close()
	st, err := store.Open(ctx, url, url, log, store.Options{AppRole: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return &tenant.DB{App: st.App, Maint: st.Maint, Log: log}
}

// newOrg adds an organisation that the test's cleanup removes, with
// everything that cascades from it.
func newOrg(t *testing.T, db *tenant.DB) string {
	t.Helper()
	ctx := t.Context()
	orgID := "dlpdet_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	if err := db.Bypass(ctx, "test seed", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, slug, name) VALUES ($1,$1,$1)`, orgID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Bypass(context.Background(), "test cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
			return err
		})
	})
	return orgID
}

// TestCustomDetectorLifecycle drives a detector through the reader the
// tool-call path uses: create, isolation between tenants, a policy that
// names it, an edit refused for a stale version or a broken sample, a
// disabled detector that does not fall back to the built-ins, a delete
// refused while a policy names it and forced through it, and a restore.
func TestCustomDetectorLifecycle(t *testing.T) {
	t.Parallel()
	db := openTenantDB(t)
	ctx := t.Context()
	orgA, orgB := newOrg(t, db), newOrg(t, db)
	revisions := governance.New(db, uuid.NewString)
	policies := dlp.NewPolicies(db, nil)
	policies.Revisions = revisions

	created, err := policies.CreateDetector(ctx, orgA, dlp.CustomDetector{Name: "contract_id", Description: "Contract ids",
		Pattern: `\bCN-\d{6}\b`, MustMatch: []string{"CN-123456"}, MustNotMatch: []string{"CN-12"}, Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Version != 1 || created.Detector != "custom:contract_id" || created.ID == "" {
		t.Errorf("created %+v", created)
	}
	if _, err := policies.CreateDetector(ctx, orgA, dlp.CustomDetector{Name: "contract_id", Pattern: `CN-\d+`,
		Enabled: true}); !errors.Is(err, dlp.ErrDetectorNameTaken) {
		t.Errorf("a second detector of the same name: %v", err)
	}
	if _, err := policies.CreateDetector(ctx, orgA, dlp.CustomDetector{Name: "broken", Pattern: `CN-\d+`,
		MustMatch: []string{"cn-1"}, Enabled: true}); !errors.Is(err, dlp.ErrInvalidDetector) {
		t.Errorf("a detector whose sample fails: %v", err)
	}

	// Another tenant may use the same name, and sees none of this one's.
	other, err := policies.CreateDetector(ctx, orgB, dlp.CustomDetector{Name: "contract_id", Pattern: `\bB-\d{4}\b`, Enabled: true})
	if err != nil {
		t.Fatalf("the same name in another organisation: %v", err)
	}
	if _, err := policies.GetDetector(ctx, orgB, created.ID); !errors.Is(err, dlp.ErrDetectorNotFound) {
		t.Errorf("organisation B read A's detector: %v", err)
	}
	if list, err := policies.ListDetectors(ctx, orgB); err != nil || len(list) != 1 || list[0].ID != other.ID {
		t.Errorf("organisation B lists %+v, %v", list, err)
	}
	if _, _, err := policies.UpdateDetector(ctx, orgB, created.ID, dlp.DetectorPatch{}, 1, ""); !errors.Is(err, dlp.ErrDetectorNotFound) {
		t.Errorf("organisation B edited A's detector: %v", err)
	}
	if _, _, err := policies.DeleteDetector(ctx, orgB, created.ID, true, ""); !errors.Is(err, dlp.ErrDetectorNotFound) {
		t.Errorf("organisation B deleted A's detector: %v", err)
	}

	// A policy names it the way it names a built-in; a name the
	// organisation does not have is refused.
	if _, err := policies.Create(ctx, orgA, dlp.ScanPolicy{Name: "nope", Scan: dlp.StageBoth, Action: dlp.ActionMask,
		Enabled: true, Detectors: []string{"custom:not_here"}}); !errors.Is(err, dlp.ErrInvalid) {
		t.Errorf("a policy naming a detector that does not exist: %v", err)
	}
	rule, err := policies.Create(ctx, orgA, dlp.ScanPolicy{Name: "Contracts", Scan: dlp.StageBoth, Action: dlp.ActionMask,
		Enabled: true, Detectors: []string{"custom:contract_id"}})
	if err != nil {
		t.Fatalf("a policy naming the detector: %v", err)
	}
	args := map[string]any{"ref": "renew CN-123456", "to": "alice@example.com"}
	scr, err := policies.Screen(ctx, orgA, "", "", dlp.StageArguments, args)
	if err != nil {
		t.Fatal(err)
	}
	if got := scr.Value.(map[string]any); got["ref"] != "renew <redacted:custom:contract_id>" || got["to"] != "alice@example.com" {
		t.Errorf("screened %v", got)
	}

	// An edit names the version it read.
	pattern := `\bCN-\d{7}\b`
	if _, _, err := policies.UpdateDetector(ctx, orgA, created.ID, dlp.DetectorPatch{Pattern: &pattern}, 7, ""); !errors.Is(err, dlp.ErrVersionConflict) {
		t.Errorf("a stale version: %v", err)
	} else if stale := (*dlp.VersionConflictError)(nil); !errors.As(err, &stale) || stale.Current != 1 {
		t.Errorf("the conflict carries %+v", stale)
	}
	// And is checked against the samples saved before.
	var de *dlp.DetectorError
	if _, _, err := policies.UpdateDetector(ctx, orgA, created.ID, dlp.DetectorPatch{Pattern: &pattern}, 1, ""); !errors.As(err, &de) || de.Field != "mustMatch[0]" {
		t.Errorf("an edit that breaks a saved sample: %v", err)
	}

	// Switched off, it drops out of the policy, and the policy does not
	// start scanning for every built-in instead.
	off := false
	_, disabled, err := policies.UpdateDetector(ctx, orgA, created.ID, dlp.DetectorPatch{Enabled: &off}, 1, "")
	if err != nil || disabled.Version != 2 {
		t.Fatalf("disable: %+v, %v", disabled, err)
	}
	scr, err = policies.Screen(ctx, orgA, "", "", dlp.StageArguments, args)
	if err != nil {
		t.Fatal(err)
	}
	if got := scr.Value.(map[string]any); got["ref"] != "renew CN-123456" || got["to"] != "alice@example.com" || scr.Result.Matches != 0 {
		t.Errorf("with the detector off: %v, %+v", got, scr.Result)
	}
	on := true
	if _, _, err := policies.UpdateDetector(ctx, orgA, created.ID, dlp.DetectorPatch{Enabled: &on}, 2, ""); err != nil {
		t.Fatal(err)
	}

	// A delete is refused while the policy names it, and names the policy.
	var inUse *dlp.InUseError
	if _, _, err := policies.DeleteDetector(ctx, orgA, created.ID, false, ""); !errors.As(err, &inUse) ||
		len(inUse.Policies) != 1 || inUse.Policies[0].ID != rule.ID || inUse.Policies[0].Name != "Contracts" {
		t.Fatalf("delete while in use: %v", err)
	}
	if _, err := policies.GetDetector(ctx, orgA, created.ID); err != nil {
		t.Fatalf("a refused delete removed the detector: %v", err)
	}
	// Forced, it leaves the policy in the same transaction; the policy,
	// left with no detector, is switched off, and its history says so.
	_, changed, err := policies.DeleteDetector(ctx, orgA, created.ID, true, "")
	if err != nil {
		t.Fatalf("forced delete: %v", err)
	}
	if len(changed) != 1 || len(changed[0].After.Detectors) != 0 || changed[0].After.Enabled || !changed[0].Before.Enabled {
		t.Errorf("the policy after a forced delete: %+v", changed)
	}
	after, err := policies.Get(ctx, orgA, rule.ID)
	if err != nil || after.Enabled || len(after.Detectors) != 0 {
		t.Errorf("the stored policy: %+v, %v", after, err)
	}
	policyHistory, err := revisions.List(ctx, orgA, governance.KindDLPPolicy, rule.ID, 0, 10)
	if err != nil || len(policyHistory) != 2 || policyHistory[0].Action != governance.ActionUpdate {
		t.Errorf("the policy's history: %+v, %v", policyHistory, err)
	}
	history, err := revisions.List(ctx, orgA, governance.KindDLPDetector, created.ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	actions := make([]string, 0, len(history))
	for _, r := range history {
		actions = append(actions, r.Action)
	}
	if !slices.Equal(actions, []string{"delete", "update", "update", "create"}) {
		t.Errorf("the detector's history: %v", actions)
	}

	// The history keeps how many samples there were, never the samples.
	snap, err := revisions.Snapshot(ctx, orgA, governance.KindDLPDetector, created.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := snap["mustMatch"]; has || snap["mustMatchCount"] != float64(1) || snap["mustNotMatchCount"] != float64(1) {
		t.Errorf("the snapshot holds %v", snap)
	}
	for _, r := range history {
		if strings.Contains(string(r.Snapshot), "CN-123456") || (r.Diff != nil && strings.Contains(fmt.Sprint(r.Diff), "CN-123456")) {
			t.Errorf("revision %d quotes a sample", r.Number)
		}
	}
	// The first revision brings it back under its old id and name, with
	// no samples: the history has none to give back.
	restored, replaced, kept, err := policies.RestoreDetector(ctx, orgA, created.ID, dlp.CustomDetector{Name: snap["name"].(string),
		Pattern: snap["pattern"].(string), Enabled: true}, "")
	if err != nil || replaced != nil || kept || restored.ID != created.ID || restored.Detector != "custom:contract_id" ||
		len(restored.MustMatch) != 0 {
		t.Errorf("restore of a deleted detector: %+v, %v, %v, %v", restored, replaced, kept, err)
	}
	// A detector that exists keeps its samples through a restore, and the
	// restored pattern is checked against them.
	withSamples := []string{"CN-123456"}
	if _, _, err := policies.UpdateDetector(ctx, orgA, created.ID, dlp.DetectorPatch{MustMatch: &withSamples}, restored.Version, ""); err != nil {
		t.Fatal(err)
	}
	restored, replaced, kept, err = policies.RestoreDetector(ctx, orgA, created.ID, dlp.CustomDetector{Pattern: `\bCN-\d{6}\b`, Enabled: true}, "")
	if err != nil || replaced == nil || !kept || len(restored.MustMatch) != 1 {
		t.Errorf("restore of an existing detector: %+v, %v, %v", restored, kept, err)
	}
	if _, _, _, err := policies.RestoreDetector(ctx, orgA, created.ID, dlp.CustomDetector{Pattern: `\bXY-\d{6}\b`, Enabled: true}, ""); !errors.Is(err, dlp.ErrInvalidDetector) {
		t.Errorf("a restore whose pattern fails the kept samples: %v", err)
	}
}

// TestCustomDetectorCostBudget: a policy whose custom detectors together
// cost more than the budget at the bytes it reads is refused at save, and
// so is an edit that would push a policy naming the detector over it.
func TestCustomDetectorCostBudget(t *testing.T) {
	t.Parallel()
	db := openTenantDB(t)
	ctx := t.Context()
	org := newOrg(t, db)
	policies := dlp.NewPolicies(db, nil)

	// \w{1,100}Q is about 200 instructions: one fits a 64 KiB policy, two
	// do not.
	big := `\w{1,100}Q`
	size, err := dlp.ProgramSize(big, "")
	if err != nil || size*dlp.DefaultMaxBytes > dlp.ScanCostBudget || 2*size*dlp.DefaultMaxBytes <= dlp.ScanCostBudget {
		t.Fatalf("the fixture is %d instructions (%v); it must fit the budget once and not twice", size, err)
	}
	for _, name := range []string{"big_one", "big_two"} {
		if _, err := policies.CreateDetector(ctx, org, dlp.CustomDetector{Name: name, Pattern: big, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	small, err := policies.CreateDetector(ctx, org, dlp.CustomDetector{Name: "small", Pattern: `\bCN-\d{6}\b`, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policies.Create(ctx, org, dlp.ScanPolicy{Name: "too much", Scan: dlp.StageBoth, Action: dlp.ActionMask,
		Enabled: true, Detectors: []string{"custom:big_one", "custom:big_two"}}); !errors.Is(err, dlp.ErrInvalid) ||
		!strings.Contains(err.Error(), "instructions") {
		t.Errorf("two large detectors at 64 KiB: %v", err)
	}
	// The same pair fits a policy that reads less.
	if _, err := policies.Create(ctx, org, dlp.ScanPolicy{Name: "small window", Scan: dlp.StageBoth, Action: dlp.ActionMask,
		Enabled: true, MaxBytes: 16 << 10, Detectors: []string{"custom:big_one", "custom:big_two"}}); err != nil {
		t.Errorf("two large detectors at 16 KiB: %v", err)
	}
	// A policy of one large and one small detector fits, until the small
	// one is edited into a large one.
	conn := newConnector(t, db, org)
	if _, err := policies.Create(ctx, org, dlp.ScanPolicy{Name: "mixed", ConnectorID: conn, Scan: dlp.StageBoth,
		Action: dlp.ActionMask, Enabled: true, Detectors: []string{"custom:big_one", "custom:small"}}); err != nil {
		t.Fatalf("one large and one small: %v", err)
	}
	var de *dlp.DetectorError
	if _, _, err := policies.UpdateDetector(ctx, org, small.ID, dlp.DetectorPatch{Pattern: &big}, small.Version, ""); !errors.As(err, &de) ||
		de.Field != "pattern" || !strings.Contains(de.Reason, `"mixed"`) {
		t.Errorf("an edit pushing a policy over the budget: %v", err)
	}
}

// TestBrokenDetectorFailsClosed: a stored detector that no longer
// compiles costs only the policies that name it, which refuse; every
// other policy in the organisation screens as before, and the failure is
// read once per load rather than once per call.
func TestBrokenDetectorFailsClosed(t *testing.T) {
	t.Parallel()
	db := openTenantDB(t)
	ctx := t.Context()
	org := newOrg(t, db)
	policies := dlp.NewPolicies(db, nil)
	if _, err := policies.CreateDetector(ctx, org, dlp.CustomDetector{Name: "contract_id", Pattern: `\bCN-\d{6}\b`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// Written by hand: the table's own checks pass, the package's do not
	// (it matches the empty string).
	if err := db.Bypass(ctx, "test seed", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO dlp_detectors (id, organization_id, name, pattern) VALUES ($1, $2, 'broken', 'x*y*')`,
			org+"_broken", org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	conn := newConnector(t, db, org)
	if _, err := policies.Create(ctx, org, dlp.ScanPolicy{Name: "fine", Scan: dlp.StageBoth, Action: dlp.ActionMask,
		Enabled: true, Detectors: []string{"custom:contract_id"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := policies.Create(ctx, org, dlp.ScanPolicy{Name: "names the broken one", ConnectorID: conn, Scan: dlp.StageBoth,
		Action: dlp.ActionAllow, Enabled: true, Detectors: []string{"custom:contract_id", "custom:broken"}}); err != nil {
		t.Fatalf("a policy may name a detector that exists: %v", err)
	}

	scr, err := policies.Screen(ctx, org, "other", "", dlp.StageArguments, map[string]any{"a": "CN-123456"})
	if err != nil || scr.Value.(map[string]any)["a"] != "<redacted:custom:contract_id>" {
		t.Errorf("a policy not naming the broken detector: %v, %v", scr.Value, err)
	}
	for range 2 {
		_, err = policies.Screen(ctx, org, conn, "", dlp.StageArguments, map[string]any{"a": "nothing here"})
		if !errors.Is(err, dlp.ErrRefused) || !errors.Is(err, dlp.ErrDetectorBroken) || !strings.Contains(err.Error(), "custom:broken") {
			t.Errorf("a policy naming the broken detector, even set to allow: %v", err)
		}
	}
}

// TestScreenRefusesPastTheCallDeadline: a screen runs under the call's
// own deadline, and one that reaches it refuses.
func TestScreenRefusesPastTheCallDeadline(t *testing.T) {
	t.Parallel()
	db := openTenantDB(t)
	ctx := t.Context()
	org := newOrg(t, db)
	policies := dlp.NewPolicies(db, nil)
	if _, err := policies.CreateDetector(ctx, org, dlp.CustomDetector{Name: "contract_id", Pattern: `\bCN-\d{6}\b`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := policies.Create(ctx, org, dlp.ScanPolicy{Name: "p", Scan: dlp.StageBoth, Action: dlp.ActionAllow,
		Enabled: true, Detectors: []string{"custom:contract_id"}}); err != nil {
		t.Fatal(err)
	}
	// Warm the cache, so the expired call below reaches the scan and not
	// the database.
	if _, err := policies.Screen(ctx, org, "", "", dlp.StageArguments, map[string]any{"a": "x"}); err != nil {
		t.Fatal(err)
	}
	expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()
	if _, err := policies.Screen(expired, org, "", "", dlp.StageArguments, map[string]any{"a": "x"}); !errors.Is(err, dlp.ErrScanDeadline) ||
		!errors.Is(err, dlp.ErrRefused) {
		t.Errorf("a screen past the call's deadline: %v", err)
	}
}

// TestDetectorVersionMovesWithThePattern: a pattern changed by hand,
// without the version, still moves the version, so no replica keeps the
// old program under the new row.
func TestDetectorVersionMovesWithThePattern(t *testing.T) {
	t.Parallel()
	db := openTenantDB(t)
	ctx := t.Context()
	org := newOrg(t, db)
	policies := dlp.NewPolicies(db, nil)
	d, err := policies.CreateDetector(ctx, org, dlp.CustomDetector{Name: "contract_id", Pattern: `\bCN-\d{6}\b`, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Bypass(ctx, "test", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE dlp_detectors SET pattern = 'CT-[0-9]{8}' WHERE id = $1`, d.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got, err := policies.GetDetector(ctx, org, d.ID)
	if err != nil || got.Version != d.Version+1 {
		t.Errorf("after a hand edit: version %d, want %d (%v)", got.Version, d.Version+1, err)
	}
	// An edit through the package moves it once, not twice.
	desc := "x"
	_, after, err := policies.UpdateDetector(ctx, org, d.ID, dlp.DetectorPatch{Description: &desc}, got.Version, "")
	if err != nil || after.Version != got.Version+1 {
		t.Errorf("after an edit: version %d, want %d (%v)", after.Version, got.Version+1, err)
	}
}

// newConnector adds a connector to scope a second policy to.
func newConnector(t *testing.T, db *tenant.DB, org string) string {
	t.Helper()
	ctx := t.Context()
	id := org + "_c" + strings.ReplaceAll(uuid.NewString(), "-", "")[:6]
	if err := db.Bypass(ctx, "test seed", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO connectors (id, organization_id, name, transport, auth) VALUES ($1,$2,'c','{}','{}')`, id, org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}
