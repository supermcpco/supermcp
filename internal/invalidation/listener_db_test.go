package invalidation_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/dlp"
	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/invalidation"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// propagation is how long a change may take to reach the other replica.
// Delivery is milliseconds; the margin is for a loaded CI runner under
// -race. The caches under test hold entries for an hour, so anything
// inside this window can only have come from a notification.
const propagation = 2 * time.Second

// fixture is one organisation with one user holding one custom role.
type fixture struct {
	url                        string
	db                         *tenant.DB
	org, user, role, bindingID string
}

func setup(t *testing.T) fixture {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	mst, err := store.Open(ctx, url, url, log, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := mst.Migrate(ctx, true); err != nil {
		mst.Close()
		t.Fatal(err)
	}
	mst.Close()
	st, err := store.Open(ctx, url, url, log, store.Options{AppRole: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}

	s := suffix(t)
	f := fixture{url: url, db: db, org: "inv_org_" + s, user: "inv_user_" + s, role: "inv_role_" + s, bindingID: "inv_rb_" + s}
	seed := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users (id, email, name) VALUES ($1, $1 || '@inv.test', 'Inv')`, []any{f.user}},
		{`INSERT INTO organizations (id, slug, name) VALUES ($1, $1, 'Inv')`, []any{f.org}},
		{`INSERT INTO organization_members (user_id, organization_id) VALUES ($1, $2)`, []any{f.user, f.org}},
		{`INSERT INTO roles (id, organization_id, name, permissions) VALUES ($1, $2, 'reader', '{tools:read}')`, []any{f.role, f.org}},
		{`INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id) VALUES ($1, $2, 'user', $3, $4)`,
			[]any{f.bindingID, f.org, f.user, f.role}},
	}
	if err := db.Bypass(ctx, "test seed", func(tx pgx.Tx) error {
		for _, s := range seed {
			if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Bypass(context.Background(), "test cleanup", func(tx pgx.Tx) error {
			if _, err := tx.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, f.org); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, f.user)
			return err
		})
	})
	return f
}

// startListener runs one simulated replica's listener: its own connection,
// and the caches registered with it. It returns once the listener is up.
func startListener(t *testing.T, f fixture, name string, caches map[invalidation.Kind]invalidation.Cache) (*invalidation.Listener, *observer) {
	t.Helper()
	obs := &observer{counts: map[string]int{}}
	l := invalidation.NewListener(invalidation.Options{
		URL: f.url, Prober: f.db.Maint, ApplicationName: name, Observer: obs,
		MinBackoff: 20 * time.Millisecond, MaxBackoff: 200 * time.Millisecond,
	})
	for kind, c := range caches {
		l.Register(kind, c)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = l.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	eventually(t, 10*time.Second, "listener "+name+" connects", l.Connected)
	return l, obs
}

func TestRevokedBindingReachesOtherReplicas(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	p := &authz.Principal{Kind: authz.KindUser, ID: f.user, OrgID: f.org}

	// Three replicas. The first makes the change; the second listens; the
	// third does not, and shows what the second would have done without
	// it.
	writer, listening, deaf := authz.New(f.db), authz.New(f.db), authz.New(f.db)
	for _, e := range []*authz.Evaluator{writer, listening, deaf} {
		e.TTL = time.Hour
	}
	startListener(t, f, "inv-authz-"+f.org, map[invalidation.Kind]invalidation.Cache{invalidation.KindAuthz: listening})

	for name, e := range map[string]*authz.Evaluator{"writer": writer, "listening": listening, "deaf": deaf} {
		d, err := e.Evaluate(ctx, p, authz.ToolsRead, authz.Resource{})
		if err != nil || !d.Allow {
			t.Fatalf("%s before the revocation: %+v, %v", name, d, err)
		}
	}

	// The revocation, the way the roles API makes it: through the tenant
	// transaction, then a local invalidation on the writing replica.
	if err := f.db.Tx(tenant.WithOrg(ctx, f.org), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM role_bindings WHERE id = $1`, f.bindingID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	writer.Invalidate(f.org, "user", f.user)

	eventually(t, propagation, "the listening replica refuses", func() bool {
		d, err := listening.Evaluate(ctx, p, authz.ToolsRead, authz.Resource{})
		return err == nil && !d.Allow
	})
	t.Logf("revocation reached the other replica in %s", time.Since(start))

	d, err := writer.Evaluate(ctx, p, authz.ToolsRead, authz.Resource{})
	if err != nil || d.Allow {
		t.Errorf("writer after the revocation: %+v, %v", d, err)
	}
	d, err = deaf.Evaluate(ctx, p, authz.ToolsRead, authz.Resource{})
	if err != nil || !d.Allow {
		t.Errorf("a replica without the listener should still answer from its cache (that is the bug this fixes): %+v, %v", d, err)
	}
}

// TestDeactivatedMemberReachesOtherReplicas deactivates a member whose
// bindings stay in place: only the membership row changes, so only the
// trigger on organization_members can tell the other replicas.
func TestDeactivatedMemberReachesOtherReplicas(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	p := &authz.Principal{Kind: authz.KindUser, ID: f.user, OrgID: f.org}

	writer, listening, deaf := authz.New(f.db), authz.New(f.db), authz.New(f.db)
	for _, e := range []*authz.Evaluator{writer, listening, deaf} {
		e.TTL = time.Hour
	}
	startListener(t, f, "inv-member-"+f.org, map[invalidation.Kind]invalidation.Cache{invalidation.KindAuthz: listening})

	for name, e := range map[string]*authz.Evaluator{"writer": writer, "listening": listening, "deaf": deaf} {
		d, err := e.Evaluate(ctx, p, authz.ToolsRead, authz.Resource{})
		if err != nil || !d.Allow {
			t.Fatalf("%s before the deactivation: %+v, %v", name, d, err)
		}
	}

	// The deactivation, the way the members API makes it, then a local
	// invalidation on the writing replica.
	members := identity.New(f.db, identity.Config{}, writer, nil)
	if _, after, _, err := members.SetMemberStatus(ctx, f.org, "inv_admin", f.user, false); err != nil || after.Status != identity.MemberDeactivated {
		t.Fatalf("deactivate: %+v, %v", after, err)
	}
	start := time.Now()
	writer.Invalidate(f.org, "user", f.user)

	eventually(t, propagation, "the listening replica refuses the deactivated member", func() bool {
		d, err := listening.Evaluate(ctx, p, authz.ToolsRead, authz.Resource{})
		return err == nil && !d.Allow
	})
	t.Logf("deactivation reached the other replica in %s", time.Since(start))

	d, err := deaf.Evaluate(ctx, p, authz.ToolsRead, authz.Resource{})
	if err != nil || !d.Allow {
		t.Errorf("a replica without the listener should still answer from its cache (that is the bug this fixes): %+v, %v", d, err)
	}
}

func TestChangedRolePermissionsReachOtherReplicas(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	p := &authz.Principal{Kind: authz.KindUser, ID: f.user, OrgID: f.org}
	listening := authz.New(f.db)
	listening.TTL = time.Hour
	startListener(t, f, "inv-role-"+f.org, map[invalidation.Kind]invalidation.Cache{invalidation.KindAuthz: listening})

	if d, err := listening.Evaluate(ctx, p, authz.ToolsRead, authz.Resource{}); err != nil || !d.Allow {
		t.Fatalf("before: %+v, %v", d, err)
	}
	// Taking a permission out of a role touches no binding, so only the
	// trigger on roles can say it happened.
	if err := f.db.Tx(tenant.WithOrg(ctx, f.org), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE roles SET permissions = '{connectors:read}' WHERE id = $1`, f.role)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, propagation, "the narrowed role applies", func() bool {
		d, err := listening.Evaluate(ctx, p, authz.ToolsRead, authz.Resource{})
		return err == nil && !d.Allow
	})
}

func TestChangedDLPPolicyReachesOtherReplicas(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	writer, listening := dlp.NewPolicies(f.db, nil), dlp.NewPolicies(f.db, nil)
	startListener(t, f, "inv-dlp-"+f.org, map[invalidation.Kind]invalidation.Cache{invalidation.KindDLP: listening})

	rule, err := writer.Create(ctx, f.org, dlp.ScanPolicy{Name: "mask", Scan: dlp.StageBoth, Action: dlp.ActionMask, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, propagation, "the listening replica sees the new rule", func() bool {
		got, found, err := listening.Resolve(ctx, f.org, "", "")
		return err == nil && found && got.Action == dlp.ActionMask
	})

	// Now cached on the listening replica. Tighten the rule elsewhere.
	start := time.Now()
	if _, err := writer.Update(ctx, f.org, rule.ID, dlp.ScanPolicy{Name: "refuse", Scan: dlp.StageBoth,
		Action: dlp.ActionRefuse, Enabled: true}, ""); err != nil {
		t.Fatal(err)
	}
	eventually(t, propagation, "the listening replica refuses", func() bool {
		got, found, err := listening.Resolve(ctx, f.org, "", "")
		return err == nil && found && got.Action == dlp.ActionRefuse
	})
	t.Logf("policy change reached the other replica in %s", time.Since(start))

	if err := writer.Delete(ctx, f.org, rule.ID, ""); err != nil {
		t.Fatal(err)
	}
	eventually(t, propagation, "the listening replica drops the deleted rule", func() bool {
		_, found, err := listening.Resolve(ctx, f.org, "", "")
		return err == nil && !found
	})
}

// TestChangedDLPDetectorReachesOtherReplicas edits a custom detector on
// one reader and sees another reader, which had the old pattern compiled
// and cached for thirty seconds, screen with the new one well inside that.
func TestChangedDLPDetectorReachesOtherReplicas(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	writer, listening := dlp.NewPolicies(f.db, nil), dlp.NewPolicies(f.db, nil)
	startListener(t, f, "inv-dlpdet-"+f.org, map[invalidation.Kind]invalidation.Cache{invalidation.KindDLP: listening})

	det, err := writer.CreateDetector(ctx, f.org, dlp.CustomDetector{Name: "contract_id", Pattern: `\bCN-\d{6}\b`, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Create(ctx, f.org, dlp.ScanPolicy{Name: "contracts", Scan: dlp.StageBoth, Action: dlp.ActionMask,
		Enabled: true, Detectors: []string{det.Ref()}}); err != nil {
		t.Fatal(err)
	}
	masked := func(v string) bool {
		scr, err := listening.Screen(ctx, f.org, "", "", dlp.StageArguments, map[string]any{"ref": v})
		return err == nil && scr.Value.(map[string]any)["ref"] == "<redacted:custom:contract_id>"
	}
	eventually(t, propagation, "the listening replica masks the old shape", func() bool { return masked("CN-123456") })

	// Now compiled and cached there. Change the shape elsewhere.
	start := time.Now()
	pattern := `\bCT-\d{8}\b`
	if _, _, err := writer.UpdateDetector(ctx, f.org, det.ID, dlp.DetectorPatch{Pattern: &pattern}, det.Version, ""); err != nil {
		t.Fatal(err)
	}
	eventually(t, propagation, "the listening replica masks the new shape and not the old", func() bool {
		return masked("CT-12345678") && !masked("CN-123456")
	})
	t.Logf("detector change reached the other replica in %s", time.Since(start))
}

// TestReconnectFlushes loses a notification on purpose and shows the
// reconnect is what recovers from it.
func TestReconnectFlushes(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	p := &authz.Principal{Kind: authz.KindUser, ID: f.user, OrgID: f.org}
	listening := authz.New(f.db)
	listening.TTL = time.Hour
	name := "inv-reconnect-" + f.org
	l, obs := startListener(t, f, name, map[invalidation.Kind]invalidation.Cache{invalidation.KindAuthz: listening})

	if d, err := listening.Evaluate(ctx, p, authz.ToolsRead, authz.Resource{}); err != nil || !d.Allow {
		t.Fatalf("before: %+v, %v", d, err)
	}
	// A revocation whose notification never arrives: triggers are off for
	// this transaction, as they would be for a notification sent while the
	// listener was away.
	if err := f.db.Bypass(ctx, "test: a missed notification", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM role_bindings WHERE id = $1`, f.bindingID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if d, err := listening.Evaluate(ctx, p, authz.ToolsRead, authz.Resource{}); err != nil || !d.Allow {
		t.Fatalf("with the notification lost, the cache should still answer: %+v, %v", d, err)
	}
	reconnectsBefore := obs.count("authz/reconnect")

	// Drop the listener's connection from the server side.
	var killed int
	if err := f.db.Maint.QueryRow(ctx, `SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE application_name = $1`, name).Scan(&killed); err != nil {
		t.Fatal(err)
	}
	if killed != 1 {
		t.Fatalf("terminated %d listener sessions, want 1", killed)
	}
	eventually(t, 10*time.Second, "the listener reconnects and flushes", func() bool {
		return l.Connected() && obs.count("authz/reconnect") > reconnectsBefore
	})
	if d, err := listening.Evaluate(ctx, p, authz.ToolsRead, authz.Resource{}); err != nil || d.Allow {
		t.Errorf("after the reconnect the revocation should apply: %+v, %v", d, err)
	}
}

// TestTriggersNotifyEveryPath checks the payloads, including the rows no
// service code touches: those removed by a cascade.
func TestTriggersNotifyEveryPath(t *testing.T) {
	t.Parallel()
	f := setup(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, f.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err := conn.Exec(ctx, "LISTEN "+invalidation.Channel); err != nil {
		t.Fatal(err)
	}
	s := suffix(t)
	connID, toolID, ruleID, policyID := "inv_c_"+s, "inv_t_"+s, "inv_tar_"+s, "inv_dp_"+s
	detectorID := "inv_dd_" + s
	tests := []struct {
		name string
		sql  string
		args []any
		want []string
	}{
		{name: "grant", sql: `INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id, scope_kind, scope_id)
			VALUES ($1, $2, 'user', $3, $4, 'server', 'srv')`, args: []any{"inv_rb2_" + s, f.org, f.user, f.role},
			want: []string{"authz:" + f.org}},
		{name: "tool access rule", sql: `INSERT INTO tool_access_rules (id, organization_id, tool_id, role_id, effect) VALUES ($1, $2, 't', $3, 'deny')`,
			args: []any{ruleID, f.org, f.role}, want: []string{"authz:" + f.org}},
		{name: "a no-op update says nothing", sql: `UPDATE roles SET name = name WHERE id = $1`, args: []any{f.role}},
		{name: "deleting a role cascades to its bindings and rules, one notification",
			sql: `DELETE FROM roles WHERE id = $1`, args: []any{f.role}, want: []string{"authz:" + f.org}},
		{name: "connector", sql: `INSERT INTO connectors (id, organization_id, name, transport, auth) VALUES ($1, $2, 'C', '{}', '{}')`,
			args: []any{connID, f.org}},
		{name: "tool", sql: `INSERT INTO tools (id, connector_id, organization_id, name, definition) VALUES ($1, $2, $3, 'x', '{}')`,
			args: []any{toolID, connID, f.org}},
		{name: "dlp policy", sql: `INSERT INTO dlp_policies (id, organization_id, name, connector_id, tool_id, action) VALUES ($1, $2, 'p', $3, $4, 'mask')`,
			args: []any{policyID, f.org, connID, toolID}, want: []string{"dlp:" + f.org}},
		{name: "deleting the connector cascades to the policy", sql: `DELETE FROM connectors WHERE id = $1`,
			args: []any{connID}, want: []string{"dlp:" + f.org}},
		{name: "custom detector", sql: `INSERT INTO dlp_detectors (id, organization_id, name, pattern) VALUES ($1, $2, 'contract', 'CN-[0-9]{6}')`,
			args: []any{detectorID, f.org}, want: []string{"dlp:" + f.org}},
		{name: "a custom detector's edit", sql: `UPDATE dlp_detectors SET enabled = false, version = version + 1 WHERE id = $1`,
			args: []any{detectorID}, want: []string{"dlp:" + f.org}},
		{name: "a custom detector's delete", sql: `DELETE FROM dlp_detectors WHERE id = $1`,
			args: []any{detectorID}, want: []string{"dlp:" + f.org}},
		{name: "deactivating a member", sql: `UPDATE organization_members SET deactivated_at = now()
			WHERE organization_id = $1 AND user_id = $2`, args: []any{f.org, f.user}, want: []string{"authz:" + f.org}},
		{name: "a membership update that leaves deactivated_at alone says nothing",
			sql: `UPDATE organization_members SET deactivated_at = deactivated_at, created_at = created_at - interval '1 second'
			WHERE organization_id = $1 AND user_id = $2`, args: []any{f.org, f.user}},
		{name: "a column the evaluator does not read says nothing",
			sql: `UPDATE organization_members SET created_at = created_at - interval '1 second'
			WHERE organization_id = $1 AND user_id = $2`, args: []any{f.org, f.user}},
		{name: "reactivating a member", sql: `UPDATE organization_members SET deactivated_at = NULL
			WHERE organization_id = $1 AND user_id = $2`, args: []any{f.org, f.user}, want: []string{"authz:" + f.org}},
		{name: "removing a member", sql: `DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2`,
			args: []any{f.org, f.user}, want: []string{"authz:" + f.org}},
		{name: "adding a member", sql: `INSERT INTO organization_members (user_id, organization_id) VALUES ($1, $2)`,
			args: []any{f.user, f.org}, want: []string{"authz:" + f.org}},
	}
	// Run in order: each step builds on the last.
	for _, tc := range tests {
		if err := f.db.Bypass(ctx, "test", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, tc.sql, tc.args...)
			return err
		}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		// A marker sent after the change, in its own transaction, bounds
		// what the change produced: notifications arrive in commit order.
		marker := "probe:marker-" + tc.name
		if _, err := f.db.Maint.Exec(ctx, "SELECT pg_notify($1, $2)", invalidation.Channel, marker); err != nil {
			t.Fatal(err)
		}
		var got []string
		for {
			waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			n, err := conn.WaitForNotification(waitCtx)
			cancel()
			if err != nil {
				t.Fatalf("%s: waiting for notifications: %v", tc.name, err)
			}
			if n.Payload == marker {
				break
			}
			// Other tests run in parallel against the same database, so
			// only this organisation's payloads, and the everything
			// payloads no test here should cause, are counted.
			if slices.Contains([]string{"authz:" + f.org, "dlp:" + f.org, "authz:*", "dlp:*"}, n.Payload) {
				got = append(got, n.Payload)
			}
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: notifications = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// observer counts what the listener reports.
type observer struct {
	mu     sync.Mutex
	counts map[string]int
}

func (o *observer) ObserveCacheInvalidation(cache, source string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.counts[cache+"/"+source]++
}

func (o *observer) SetCacheListenerConnected(bool) {}

func (o *observer) count(key string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.counts[key]
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.After(within)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("%s: not within %s", what, within)
		case <-tick.C:
		}
	}
}

func suffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
