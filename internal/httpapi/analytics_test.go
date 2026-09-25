package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/hardening"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

func TestUsageWindowFor(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 1, 12, 30, 0, 0, time.UTC)
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	tests := []struct {
		name       string
		from, to   time.Time
		bucket     string
		wantFrom   time.Time
		wantTo     time.Time
		wantBucket string
		wantErr    string
	}{
		{name: "defaults are the last seven days by day", wantFrom: now.Add(-7 * 24 * time.Hour), wantTo: now, wantBucket: "day"},
		{name: "from defaults to seven days before to", to: at("2026-02-10T00:00:00Z"),
			wantFrom: at("2026-02-03T00:00:00Z"), wantTo: at("2026-02-10T00:00:00Z"), wantBucket: "day"},
		{name: "two days is hourly", from: now.Add(-48 * time.Hour), wantFrom: now.Add(-48 * time.Hour), wantTo: now, wantBucket: "hour"},
		{name: "a little over two days is daily", from: now.Add(-48*time.Hour - time.Minute),
			wantFrom: now.Add(-48*time.Hour - time.Minute), wantTo: now, wantBucket: "day"},
		{name: "an explicit bucket wins", from: now.Add(-30 * 24 * time.Hour), bucket: "hour",
			wantFrom: now.Add(-30 * 24 * time.Hour), wantTo: now, wantBucket: "hour"},
		{name: "exactly ninety days", from: now.Add(-90 * 24 * time.Hour), wantFrom: now.Add(-90 * 24 * time.Hour), wantTo: now, wantBucket: "day"},
		{name: "offsets are read as UTC", from: at("2026-02-01T02:00:00+02:00"), to: at("2026-02-02T02:00:00+02:00"),
			wantFrom: at("2026-02-01T00:00:00Z"), wantTo: at("2026-02-02T00:00:00Z"), wantBucket: "hour"},
		{name: "wider than ninety days", from: now.Add(-90*24*time.Hour - time.Second), wantErr: "at most 90 days"},
		{name: "reversed", from: now.Add(time.Hour), wantErr: "must be before"},
		{name: "empty", from: now, to: now, wantErr: "must be before"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w, err := usageWindowFor(now, tt.from, tt.to, tt.bucket)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !w.From.Equal(tt.wantFrom) || !w.To.Equal(tt.wantTo) || w.Bucket != tt.wantBucket {
				t.Errorf("got %s..%s by %s, want %s..%s by %s", w.From, w.To, w.Bucket, tt.wantFrom, tt.wantTo, tt.wantBucket)
			}
			if w.From.Location() != time.UTC || w.To.Location() != time.UTC {
				t.Errorf("window not in UTC: %s, %s", w.From.Location(), w.To.Location())
			}
		})
	}
}

// usageSeed is two organisations' calls over two days. Organisation B's
// calls sit in the same window as A's, so any leak shows up in A's counts.
const usageSeed = `
INSERT INTO users (id, email, name) VALUES
    ('an_u_a','a@analytics.test','A'), ('an_u_b','b@analytics.test','B'), ('an_u_none','none@analytics.test','N'),
    ('an_u_conn','conn@analytics.test','C');
INSERT INTO organizations (id, slug, name) VALUES ('an_a','an-a','A'), ('an_b','an-b','B');
INSERT INTO organization_members (user_id, organization_id) VALUES ('an_u_a','an_a'), ('an_u_b','an_b'), ('an_u_none','an_a'), ('an_u_conn','an_a');
INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id)
    VALUES ('an_rb_a','an_a','user','an_u_a','role_viewer'), ('an_rb_b','an_b','user','an_u_b','role_viewer');
-- May read connectors and their calls, but not the MCP servers.
INSERT INTO roles (id, organization_id, name, permissions) VALUES ('an_r_conn','an_a','connectors only','{connectors:read}');
INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id)
    VALUES ('an_rb_conn','an_a','user','an_u_conn','an_r_conn');
INSERT INTO connectors (id, organization_id, name, transport, auth)
    VALUES ('an_c1','an_a','First','{}','{}'), ('an_c2','an_a','Second','{}','{}'), ('an_cb','an_b','Theirs','{}','{}');
INSERT INTO tools (id, connector_id, organization_id, name, definition)
    VALUES ('an_t1','an_c1','an_a','alpha','{}'), ('an_t2','an_c1','an_a','beta','{}'), ('an_tb','an_cb','an_b','theirs','{}');
INSERT INTO mcp_servers (id, organization_id, slug, name) VALUES ('an_m1','an_a','main','Main'), ('an_mb','an_b','theirs','Theirs');
INSERT INTO tool_invocations (id, organization_id, server_id, connector_id, tool_id, tool_name, principal_kind, auth_method, status, duration_ms, upstream_ms, created_at) VALUES
    -- A, day one. alpha was called under an older name.
    ('an_i01','an_a','an_m1','an_c1','an_t1','alpha_before_rename','user','api_key','success', 10,  5, '2026-01-10T01:10:00Z'),
    ('an_i02','an_a','an_m1','an_c1','an_t1','alpha_before_rename','user','api_key','success', 20, 15, '2026-01-10T01:20:00Z'),
    ('an_i03','an_a','an_m1','an_c1','an_t1','alpha','user','api_key','success',               30, 25, '2026-01-10T03:00:00Z'),
    ('an_i04','an_a','an_m1','an_c1','an_t1','alpha','user','api_key','error',                 40, NULL, '2026-01-10T03:30:00Z'),
    ('an_i05','an_a',NULL,   'an_c1','an_t2','beta','user','api_key','timeout',               100, NULL, '2026-01-10T05:00:00Z'),
    -- A, day two. The last tool has since been deleted.
    ('an_i06','an_a','an_m1','an_c1','an_t1','alpha','user','api_key','success',               50, 45, '2026-01-11T10:00:00Z'),
    ('an_i07','an_a',NULL,   'an_c1','an_t2','beta','user','api_key','success',                60, NULL, '2026-01-11T11:00:00Z'),
    ('an_i08','an_a','an_m1','an_c2','an_t_gone','gone_tool','user','api_key','success',        7, NULL, '2026-01-11T12:00:00Z'),
    -- A, outside the window on both sides.
    ('an_i09','an_a','an_m1','an_c1','an_t1','alpha','user','api_key','success',               99, NULL, '2026-01-09T23:59:59Z'),
    ('an_i10','an_a','an_m1','an_c1','an_t1','alpha','user','api_key','success',               99, NULL, '2026-01-12T00:00:00Z'),
    -- B, inside A's window.
    ('an_i11','an_b','an_mb','an_cb','an_tb','theirs','user','api_key','error',              1000, NULL, '2026-01-10T01:30:00Z'),
    ('an_i12','an_b','an_mb','an_cb','an_tb','theirs','user','api_key','success',            2000, NULL, '2026-01-11T01:30:00Z'),
    ('an_i13','an_b','an_mb','an_cb','an_tb','theirs','user','api_key','success',            3000, NULL, '2026-01-11T02:30:00Z');
`

const usageCleanup = `
DELETE FROM tool_invocations WHERE organization_id IN ('an_a','an_b');
DELETE FROM organizations WHERE id IN ('an_a','an_b');
DELETE FROM users WHERE id IN ('an_u_a','an_u_b','an_u_none','an_u_conn');
`

// TestUsageAgainstPostgres checks the buckets, error counts, percentiles
// and top lists of the usage endpoint, and that each organisation sees
// only its own calls. Requires DATABASE_URL.
func TestUsageAgainstPostgres(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	maint, err := store.Open(ctx, dsn, dsn, log, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := maint.Migrate(ctx, true); err != nil {
		maint.Close()
		t.Fatal(err)
	}
	maint.Close()
	st, err := store.Open(ctx, dsn, dsn, log, store.Options{AppRole: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}
	exec := func(sql string) {
		t.Helper()
		if err := db.Bypass(ctx, "analytics test", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	exec(usageCleanup)
	exec(usageSeed)
	t.Cleanup(func() { exec(usageCleanup) })

	// The guard's clock is the test's, so the cache can be expired
	// without waiting for it.
	var clockMu sync.Mutex
	clock := time.Date(2026, 1, 12, 0, 0, 0, 0, time.UTC)
	guard := newAnalyticsGuard(func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	})
	advance := func(d time.Duration) {
		clockMu.Lock()
		defer clockMu.Unlock()
		clock = clock.Add(d)
	}
	_, api := humatest.New(t)
	Deps{DB: db, Authz: authz.New(db), Log: log, analytics: guard}.analyticsRoutes(api)

	get := func(t *testing.T, user, org string, q url.Values, wantStatus int) usageReport {
		t.Helper()
		p := &authz.Principal{Kind: authz.KindUser, ID: user, OrgID: org, AuthMethod: "session"}
		resp := api.GetCtx(authz.WithPrincipal(ctx, p), "/api/v1/analytics/usage?"+q.Encode())
		if resp.Code != wantStatus {
			t.Fatalf("status %d, want %d: %s", resp.Code, wantStatus, resp.Body.String())
		}
		var rep usageReport
		if wantStatus == http.StatusOK {
			if err := json.Unmarshal(resp.Body.Bytes(), &rep); err != nil {
				t.Fatal(err)
			}
		}
		return rep
	}
	window := url.Values{"from": {"2026-01-10T00:00:00Z"}, "to": {"2026-01-12T00:00:00Z"}}
	with := func(kv ...string) url.Values {
		q := url.Values{}
		for k, v := range window {
			q[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			q.Set(kv[i], kv[i+1])
		}
		return q
	}

	t.Run("daily series and totals", func(t *testing.T) {
		rep := get(t, "an_u_a", "an_a", with("bucket", "day"), http.StatusOK)
		wantStats(t, "totals", rep.Totals, 8, 2, f(35), f(86), f(20), f(42))
		if len(rep.Series) != 2 {
			t.Fatalf("%d buckets, want 2: %+v", len(rep.Series), rep.Series)
		}
		if !rep.Series[0].Start.Equal(time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)) ||
			!rep.Series[1].Start.Equal(time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("bucket starts %s, %s", rep.Series[0].Start, rep.Series[1].Start)
		}
		wantStats(t, "day one", rep.Series[0].UsageStats, 5, 2, f(30), f(88), f(15), f(24))
		wantStats(t, "day two", rep.Series[1].UsageStats, 3, 0, f(50), f(59), f(45), f(45))
	})

	t.Run("hourly buckets are filled", func(t *testing.T) {
		rep := get(t, "an_u_a", "an_a", url.Values{"from": {"2026-01-10T00:00:00Z"}, "to": {"2026-01-10T06:00:00Z"}}, http.StatusOK)
		if rep.Bucket != "hour" {
			t.Errorf("bucket %q, want the hourly default for six hours", rep.Bucket)
		}
		var calls []int64
		for _, p := range rep.Series {
			calls = append(calls, p.Calls)
		}
		if got, want := calls, []int64{0, 2, 0, 2, 0, 1}; !slices.Equal(got, want) {
			t.Errorf("hourly calls %v, want %v", got, want)
		}
		if rep.Series[0].P50MS != nil {
			t.Errorf("an empty bucket has a median: %v", *rep.Series[0].P50MS)
		}
	})

	t.Run("a window starting mid-bucket counts only what is inside", func(t *testing.T) {
		rep := get(t, "an_u_a", "an_a", url.Values{"from": {"2026-01-10T01:15:00Z"}, "to": {"2026-01-10T03:15:00Z"}}, http.StatusOK)
		if rep.Totals.Calls != 2 || len(rep.Series) != 3 || !rep.Series[0].Start.Equal(time.Date(2026, 1, 10, 1, 0, 0, 0, time.UTC)) {
			t.Errorf("totals %d over %d buckets from %s, want 2 over 3 from 01:00", rep.Totals.Calls, len(rep.Series), rep.Series[0].Start)
		}
	})

	t.Run("top tools", func(t *testing.T) {
		rep := get(t, "an_u_a", "an_a", with("by", "tool"), http.StatusOK)
		wantTop(t, rep.Top, []usageGroup{
			{ID: "an_t1", Name: "alpha", UsageStats: UsageStats{Calls: 5, Errors: 1}},
			{ID: "an_t2", Name: "beta", UsageStats: UsageStats{Calls: 2, Errors: 1}},
			{ID: "an_t_gone", Name: "gone_tool", UsageStats: UsageStats{Calls: 1}},
		})
		wantStats(t, "alpha", rep.Top[0].UsageStats, 5, 1, f(30), f(48), f(20), f(42))
	})

	t.Run("top connectors", func(t *testing.T) {
		rep := get(t, "an_u_a", "an_a", with("by", "connector"), http.StatusOK)
		wantTop(t, rep.Top, []usageGroup{
			{ID: "an_c1", Name: "First", UsageStats: UsageStats{Calls: 7, Errors: 2}},
			{ID: "an_c2", Name: "Second", UsageStats: UsageStats{Calls: 1}},
		})
	})

	t.Run("top servers", func(t *testing.T) {
		rep := get(t, "an_u_a", "an_a", with("by", "server"), http.StatusOK)
		wantTop(t, rep.Top, []usageGroup{
			{ID: "an_m1", Name: "Main", UsageStats: UsageStats{Calls: 6, Errors: 1}},
			{ID: "", Name: "", UsageStats: UsageStats{Calls: 2, Errors: 1}},
		})
	})

	t.Run("the server breakdown needs servers:read", func(t *testing.T) {
		get(t, "an_u_conn", "an_a", with("by", "server"), http.StatusForbidden)
		// The same caller may still count calls by tool and connector.
		if rep := get(t, "an_u_conn", "an_a", with("by", "connector"), http.StatusOK); rep.Totals.Calls != 8 {
			t.Errorf("by connector: %d calls, want 8", rep.Totals.Calls)
		}
	})

	t.Run("a third concurrent query from one workspace is refused", func(t *testing.T) {
		// Two queries of A's are in flight; a new question (one the cache
		// cannot answer) is refused rather than queued behind them.
		q := with("bucket", "day", "limit", "7")
		for range usageInflightPerOrg {
			if !guard.acquire("an_a") {
				t.Fatal("could not take a slot that should be free")
			}
		}
		get(t, "an_u_a", "an_a", q, http.StatusTooManyRequests)
		// Another workspace is not held up by A's queries.
		get(t, "an_u_b", "an_b", q, http.StatusOK)
		guard.release("an_a")
		if rep := get(t, "an_u_a", "an_a", q, http.StatusOK); rep.Totals.Calls != 8 {
			t.Errorf("after a slot was freed: %d calls, want 8", rep.Totals.Calls)
		}
		guard.release("an_a")
	})

	t.Run("an answer is reused for a minute", func(t *testing.T) {
		q := with("bucket", "day", "limit", "3")
		if rep := get(t, "an_u_a", "an_a", q, http.StatusOK); rep.Totals.Calls != 8 {
			t.Fatalf("%d calls, want 8", rep.Totals.Calls)
		}
		exec(`INSERT INTO tool_invocations (id, organization_id, tool_name, principal_kind, auth_method, status, duration_ms, created_at)
			VALUES ('an_i14','an_a','late','user','api_key','success',1,'2026-01-11T13:00:00Z')`)
		if rep := get(t, "an_u_a", "an_a", q, http.StatusOK); rep.Totals.Calls != 8 {
			t.Errorf("within the minute: %d calls, want the cached 8", rep.Totals.Calls)
		}
		// Another workspace asking the same question gets its own answer.
		if rep := get(t, "an_u_b", "an_b", q, http.StatusOK); rep.Totals.Calls != 3 {
			t.Errorf("B asking A's question: %d calls, want its own 3", rep.Totals.Calls)
		}
		advance(usageCacheTTL)
		if rep := get(t, "an_u_a", "an_a", q, http.StatusOK); rep.Totals.Calls != 9 {
			t.Errorf("after the minute: %d calls, want 9", rep.Totals.Calls)
		}
		exec(`DELETE FROM tool_invocations WHERE id = 'an_i14'`)
		advance(usageCacheTTL)
	})

	t.Run("limit", func(t *testing.T) {
		rep := get(t, "an_u_a", "an_a", with("limit", "1"), http.StatusOK)
		if len(rep.Top) != 1 || rep.Top[0].ID != "an_t1" {
			t.Errorf("top with limit 1: %+v", rep.Top)
		}
	})

	t.Run("the other organisation sees only its own calls", func(t *testing.T) {
		rep := get(t, "an_u_b", "an_b", with("bucket", "day"), http.StatusOK)
		wantStats(t, "B totals", rep.Totals, 3, 1, f(2000), f(2900), nil, nil)
		wantTop(t, rep.Top, []usageGroup{{ID: "an_tb", Name: "theirs", UsageStats: UsageStats{Calls: 3, Errors: 1}}})
		if rep.Series[0].Calls != 1 || rep.Series[1].Calls != 2 {
			t.Errorf("B series %+v", rep.Series)
		}
	})

	t.Run("the query runs under row-level security", func(t *testing.T) {
		// A's rows asked for inside B's transaction: the WHERE clause
		// alone would find them, the policy must not.
		var calls int64
		err := db.Tx(tenant.WithOrg(ctx, "an_b"), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT calls FROM (`+usageSeriesSQL+`) s WHERE total`, "an_a",
				time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 12, 0, 0, 0, 0, time.UTC), "day").Scan(&calls)
		})
		if err != nil {
			t.Fatal(err)
		}
		if calls != 0 {
			t.Errorf("B's transaction counted %d of A's calls", calls)
		}
	})

	t.Run("a principal claiming another organisation reads nothing of it", func(t *testing.T) {
		// A's user has no binding in B, so the permission check refuses;
		// row-level security would have returned nothing regardless.
		get(t, "an_u_a", "an_b", window, http.StatusForbidden)
	})

	t.Run("a member without a role is refused", func(t *testing.T) {
		get(t, "an_u_none", "an_a", window, http.StatusForbidden)
	})

	for _, tc := range []struct {
		name string
		q    url.Values
	}{
		{"reversed", url.Values{"from": {"2026-01-12T00:00:00Z"}, "to": {"2026-01-10T00:00:00Z"}}},
		{"wider than 90 days", url.Values{"from": {"2025-10-01T00:00:00Z"}, "to": {"2026-01-10T00:00:00Z"}}},
		{"unknown bucket", with("bucket", "week")},
		{"unknown dimension", with("by", "principal")},
	} {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			get(t, "an_u_a", "an_a", tc.q, http.StatusUnprocessableEntity)
		})
	}
}

func f(v float64) *float64 { return &v }

func wantStats(t *testing.T, what string, got UsageStats, calls, errors int64, p50, p95, up50, up95 *float64) {
	t.Helper()
	if got.Calls != calls || got.Errors != errors {
		t.Errorf("%s: %d calls, %d errors; want %d, %d", what, got.Calls, got.Errors, calls, errors)
	}
	for _, c := range []struct {
		name      string
		got, want *float64
	}{{"p50", got.P50MS, p50}, {"p95", got.P95MS, p95}, {"upstream p50", got.UpstreamP50MS, up50}, {"upstream p95", got.UpstreamP95MS, up95}} {
		switch {
		case c.got == nil && c.want == nil:
		case c.got == nil || c.want == nil:
			t.Errorf("%s %s: got %v, want %v", what, c.name, ptr(c.got), ptr(c.want))
		case math.Abs(*c.got-*c.want) > 1e-9:
			t.Errorf("%s %s: got %v, want %v", what, c.name, *c.got, *c.want)
		}
	}
}

func ptr(v *float64) any {
	if v == nil {
		return nil
	}
	return *v
}

func wantTop(t *testing.T, got, want []usageGroup) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("top has %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.ID != w.ID || g.Name != w.Name || g.Calls != w.Calls || g.Errors != w.Errors {
			t.Errorf("top[%d] = %s %q %d calls %d errors, want %s %q %d calls %d errors",
				i, g.ID, g.Name, g.Calls, g.Errors, w.ID, w.Name, w.Calls, w.Errors)
		}
	}
}

func TestAnalyticsGuard(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g := newAnalyticsGuard(func() time.Time { return now })

	for i := range usageInflightPerOrg {
		if !g.acquire("a") {
			t.Fatalf("slot %d refused", i+1)
		}
	}
	if g.acquire("a") {
		t.Error("a third slot was granted")
	}
	if !g.acquire("b") {
		t.Error("another organisation was refused because of the first")
	}
	g.release("a")
	if !g.acquire("a") {
		t.Error("a released slot was not granted again")
	}
	g.release("a")
	g.release("a")
	g.release("b")
	if len(g.inflight) != 0 {
		t.Errorf("idle organisations left behind: %v", g.inflight)
	}

	k := usageKey{org: "a", bucket: "day", by: "tool", limit: 10}
	g.put(k, usageReport{Totals: UsageStats{Calls: 1}})
	if rep, ok := g.get(k); !ok || rep.Totals.Calls != 1 {
		t.Errorf("fresh entry: %v %v", rep, ok)
	}
	other := k
	other.org = "b"
	if _, ok := g.get(other); ok {
		t.Error("an entry was served to another organisation")
	}
	now = now.Add(usageCacheTTL)
	if _, ok := g.get(k); ok {
		t.Error("an expired entry was served")
	}
}

func TestAnalyticsBudget(t *testing.T) {
	t.Parallel()
	d := Deps{Budgets: hardening.DefaultBudgets()}
	got := d.budgetFor("/api/v1/analytics/usage")
	if got.Name != "analytics" {
		t.Fatalf("analytics draws on the %q budget", got.Name)
	}
	if api := d.budgetFor("/api/v1/tool-calls"); got.Burst >= api.Burst {
		t.Errorf("analytics budget %d is not below the API's %d", got.Burst, api.Burst)
	}
}

// TestDLPTestBudget: the routes that run detectors over text the caller
// sends draw on a budget of their own, smaller than the API's.
func TestDLPTestBudget(t *testing.T) {
	t.Parallel()
	d := Deps{Budgets: hardening.DefaultBudgets()}
	api := d.budgetFor("/api/v1/dlp/policies")
	for _, path := range []string{"/api/v1/dlp/preview", "/api/v1/dlp/detectors/test"} {
		got := d.budgetFor(path)
		if got.Name != "dlp_test" || got.Burst >= api.Burst {
			t.Errorf("%s draws on %q (%d), want dlp_test below the API's %d", path, got.Name, got.Burst, api.Burst)
		}
	}
	if got := d.budgetFor("/api/v1/dlp/detectors"); got.Name != api.Name {
		t.Errorf("the detector list draws on %q", got.Name)
	}
}
