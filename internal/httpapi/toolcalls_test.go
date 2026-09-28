package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/hardening"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

func TestToolCallsQuery(t *testing.T) {
	t.Parallel()
	since := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	until := since.Add(time.Hour)
	tests := []struct {
		name      string
		f         toolCallFilter
		wantConds []string
		wantArgs  []any
	}{
		{name: "no filter is the org and a page of 50", f: toolCallFilter{},
			wantArgs: []any{"org", 50}},
		{name: "a page over 500 is 50", f: toolCallFilter{Limit: 501}, wantArgs: []any{"org", 50}},
		{name: "a page of 500", f: toolCallFilter{Limit: 500}, wantArgs: []any{"org", 500}},
		{name: "every filter, numbered in order",
			f: toolCallFilter{Limit: 10, Since: since, Until: until, ConnectorID: "c", ServerID: "s", Status: "error", Q: "a%b"},
			wantConds: []string{"created_at >= $2", "created_at < $3", "connector_id = $4", "server_id = $5", "status = $6",
				`tool_name ILIKE '%' || $7 || '%'`},
			wantArgs: []any{"org", since, until, "c", "s", "error", `a\%b`, 10}},
		{name: "one filter takes the next number", f: toolCallFilter{ServerID: "s"},
			wantConds: []string{"server_id = $2"}, wantArgs: []any{"org", "s", 50}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sql, args := toolCallsQuery("org", tt.f)
			if !slices.Equal(args, tt.wantArgs) {
				t.Errorf("args = %v, want %v", args, tt.wantArgs)
			}
			if got, want := strings.Count(sql, " AND "), len(tt.wantConds); got != want {
				t.Errorf("%d conditions, want %d: %s", got, want, sql)
			}
			for _, c := range tt.wantConds {
				if !strings.Contains(sql, c) {
					t.Errorf("no %q in %s", c, sql)
				}
			}
			if want := "LIMIT $" + itoa(len(args)); !strings.HasSuffix(sql, want) {
				t.Errorf("does not end in %q: %s", want, sql)
			}
		})
	}
}

func TestLikeEscape(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"plain": "plain", "100%": `100\%`, "a_b": `a\_b`, `c:\x`: `c:\\x`} {
		if got := likeEscape(in); got != want {
			t.Errorf("likeEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestToolCallWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name                 string
		since, until         time.Time
		wantSince, wantUntil time.Time
		wantErr              string
	}{
		{name: "defaults are the last seven days", wantSince: now.Add(-7 * 24 * time.Hour), wantUntil: now},
		{name: "since defaults to seven days before until", until: now.Add(-24 * time.Hour),
			wantSince: now.Add(-8 * 24 * time.Hour), wantUntil: now.Add(-24 * time.Hour)},
		{name: "exactly ninety days", since: now.Add(-90 * 24 * time.Hour), wantSince: now.Add(-90 * 24 * time.Hour), wantUntil: now},
		{name: "wider than ninety days", since: now.Add(-90*24*time.Hour - time.Second), wantErr: "at most 90 days"},
		{name: "reversed", since: now.Add(time.Hour), wantErr: "must be before"},
		{name: "empty", since: now, until: now, wantErr: "must be before"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			since, until, err := toolCallWindow(now, tt.since, tt.until)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !since.Equal(tt.wantSince) || !until.Equal(tt.wantUntil) {
				t.Errorf("got %s..%s, want %s..%s", since, until, tt.wantSince, tt.wantUntil)
			}
		})
	}
}

// TestToolCallsSummaryBudget: the summary aggregates up to 90 days of
// calls, so it draws on the analytics budget; the list does not.
func TestToolCallsSummaryBudget(t *testing.T) {
	t.Parallel()
	d := Deps{Budgets: hardening.DefaultBudgets()}
	if got := d.budgetFor("/api/v1/tool-calls/summary").Name; got != "analytics" {
		t.Errorf("the summary draws on the %q budget", got)
	}
	if got := d.budgetFor("/api/v1/tool-calls").Name; got == "analytics" {
		t.Error("the list draws on the analytics budget")
	}
}

// toolCallsSeed is two organisations' calls. B has a call that names A's
// connector and server, which no tool call could, so a filter that
// forgot the organisation would show it to A.
const toolCallsSeed = `
INSERT INTO users (id, email, name) VALUES
    ('tc_u_a','a@toolcalls.test','A'), ('tc_u_b','b@toolcalls.test','B'), ('tc_u_none','none@toolcalls.test','N');
INSERT INTO organizations (id, slug, name) VALUES ('tc_a','tc-a','A'), ('tc_b','tc-b','B');
INSERT INTO organization_members (user_id, organization_id) VALUES ('tc_u_a','tc_a'), ('tc_u_b','tc_b'), ('tc_u_none','tc_a');
INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id)
    VALUES ('tc_rb_a','tc_a','user','tc_u_a','role_viewer'), ('tc_rb_b','tc_b','user','tc_u_b','role_viewer');
INSERT INTO tool_invocations (id, organization_id, server_id, connector_id, tool_id, tool_name, principal_kind, principal_id, auth_method, status, duration_ms, input, output, error, created_at) VALUES
    ('tc_i01','tc_a','tc_m1','tc_c1','tc_t1','Search_Issues','user','tc_u_a','session','success', 10, '{"q":"secret"}', '{"r":"secret"}', NULL, '2026-01-10T01:00:00Z'),
    ('tc_i02','tc_a','tc_m1','tc_c1','tc_t1','search_issues','user','tc_u_a','session','error',   20, NULL, NULL, 'boom', '2026-01-10T01:30:00Z'),
    ('tc_i03','tc_a',NULL,   'tc_c2','tc_t2','create_page','api_key','tc_k1','api_key','timeout', 30, NULL, NULL, NULL, '2026-01-10T02:00:00Z'),
    ('tc_i04','tc_a','tc_m1','tc_c2','tc_t2','create_page','anonymous',NULL,'none','denied',     40, NULL, NULL, NULL, '2026-01-10T03:00:00Z'),
    ('tc_i05','tc_a','tc_m1','tc_c1','tc_t3','rate_100%_off','user','tc_u_a','session','success', 50, NULL, NULL, NULL, '2026-01-10T04:00:00Z'),
    ('tc_i06','tc_a','tc_m1','tc_c1','tc_t4','rate_1000_off','user','tc_u_a','session','success', 60, NULL, NULL, NULL, '2026-01-10T05:00:00Z'),
    ('tc_i07','tc_a','tc_m1','tc_c1','tc_t1','search_issues','user','tc_u_a','session','success', 70, NULL, NULL, NULL, '2026-01-12T00:00:00Z'),
    ('tc_i11','tc_b','tc_mb','tc_cb','tc_tb','search_issues','user','tc_u_b','session','error',   80, NULL, NULL, 'theirs', '2026-01-10T01:15:00Z'),
    ('tc_i12','tc_b','tc_mb','tc_cb','tc_tb','create_page','user','tc_u_b','session','success',   90, NULL, NULL, NULL, '2026-01-10T02:15:00Z'),
    ('tc_i13','tc_b','tc_m1','tc_c1','tc_t1','search_issues','user','tc_u_b','session','success', 99, NULL, NULL, NULL, '2026-01-10T04:30:00Z');
`

const toolCallsCleanup = `
DELETE FROM tool_invocations WHERE organization_id IN ('tc_a','tc_b');
DELETE FROM organizations WHERE id IN ('tc_a','tc_b');
DELETE FROM users WHERE id IN ('tc_u_a','tc_u_b','tc_u_none');
`

// TestToolCallsAgainstPostgres checks each filter of the tool-call list
// and the summary, and that neither shows one organisation another's
// calls. Requires DATABASE_URL.
//
// The routes get a tenant.DB without a maintenance pool, so they can only
// read through Tx, under the workspace's row-level security role: a
// Bypass would have no pool to run on.
func TestToolCallsAgainstPostgres(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	st := openAppStore(t, dsn, log)
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}
	exec := func(sql string) {
		t.Helper()
		if err := db.Bypass(ctx, "tool calls test", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	exec(toolCallsCleanup)
	exec(toolCallsSeed)
	t.Cleanup(func() { exec(toolCallsCleanup) })

	_, api := humatest.New(t)
	Deps{DB: &tenant.DB{App: st.App, Log: log}, Authz: authz.New(db), Log: log}.invocationRoutes(api)

	get := func(t *testing.T, user, org, path string, q url.Values, wantStatus int) []byte {
		t.Helper()
		p := &authz.Principal{Kind: authz.KindUser, ID: user, OrgID: org, AuthMethod: "session"}
		resp := api.GetCtx(authz.WithPrincipal(ctx, p), path+"?"+q.Encode())
		if resp.Code != wantStatus {
			t.Fatalf("status %d, want %d: %s", resp.Code, wantStatus, resp.Body.String())
		}
		return resp.Body.Bytes()
	}
	list := func(t *testing.T, user, org string, q url.Values) []invocationDTO {
		t.Helper()
		var out []invocationDTO
		if err := json.Unmarshal(get(t, user, org, "/api/v1/tool-calls", q, http.StatusOK), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	ids := func(l []invocationDTO) []string {
		out := make([]string, 0, len(l))
		for _, i := range l {
			out = append(out, strings.TrimPrefix(i.ID, "tc_"))
		}
		return out
	}

	t.Run("filters", func(t *testing.T) {
		tests := []struct {
			name string
			user string
			org  string
			q    url.Values
			want []string
		}{
			{"no filter is every call, newest first", "tc_u_a", "tc_a", nil, []string{"i07", "i06", "i05", "i04", "i03", "i02", "i01"}},
			{"the other organisation sees its own", "tc_u_b", "tc_b", nil, []string{"i13", "i12", "i11"}},
			{"limit", "tc_u_a", "tc_a", url.Values{"limit": {"2"}}, []string{"i07", "i06"}},
			{"since is inclusive", "tc_u_a", "tc_a", url.Values{"since": {"2026-01-10T02:00:00Z"}},
				[]string{"i07", "i06", "i05", "i04", "i03"}},
			{"until is exclusive", "tc_u_a", "tc_a", url.Values{"until": {"2026-01-10T02:00:00Z"}}, []string{"i02", "i01"}},
			{"since and until, with an offset", "tc_u_a", "tc_a",
				url.Values{"since": {"2026-01-10T03:30:00+02:00"}, "until": {"2026-01-10T04:00:00Z"}}, []string{"i04", "i03", "i02"}},
			{"connector", "tc_u_a", "tc_a", url.Values{"connectorId": {"tc_c2"}}, []string{"i04", "i03"}},
			{"connector, and not another organisation's call naming it", "tc_u_a", "tc_a", url.Values{"connectorId": {"tc_c1"}},
				[]string{"i07", "i06", "i05", "i02", "i01"}},
			{"another organisation's connector", "tc_u_a", "tc_a", url.Values{"connectorId": {"tc_cb"}}, []string{}},
			{"server", "tc_u_a", "tc_a", url.Values{"serverId": {"tc_m1"}}, []string{"i07", "i06", "i05", "i04", "i02", "i01"}},
			{"another organisation's server", "tc_u_a", "tc_a", url.Values{"serverId": {"tc_mb"}}, []string{}},
			{"status", "tc_u_a", "tc_a", url.Values{"status": {"error"}}, []string{"i02"}},
			{"q ignores case", "tc_u_a", "tc_a", url.Values{"q": {"SEARCH"}}, []string{"i07", "i02", "i01"}},
			{"q takes % literally", "tc_u_a", "tc_a", url.Values{"q": {"100%"}}, []string{"i05"}},
			{"q takes _ literally", "tc_u_a", "tc_a", url.Values{"q": {"_1000"}}, []string{"i06"}},
			{"filters combine", "tc_u_a", "tc_a", url.Values{"connectorId": {"tc_c1"}, "status": {"success"},
				"since": {"2026-01-10T00:00:00Z"}, "until": {"2026-01-11T00:00:00Z"}}, []string{"i06", "i05", "i01"}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := ids(list(t, tt.user, tt.org, tt.q)); !slices.Equal(got, tt.want) {
					t.Errorf("got %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("rows name their context and nothing more", func(t *testing.T) {
		body := get(t, "tc_u_a", "tc_a", "/api/v1/tool-calls", nil, http.StatusOK)
		if strings.Contains(string(body), "secret") || strings.Contains(string(body), `"input"`) || strings.Contains(string(body), `"output"`) {
			t.Fatalf("the list carries a call's arguments or result: %s", body)
		}
		byID := map[string]invocationDTO{}
		for _, i := range list(t, "tc_u_a", "tc_a", nil) {
			byID[i.ID] = i
		}
		want := map[string]invocationDTO{
			"tc_i02": {ID: "tc_i02", ToolName: "search_issues", ToolID: "tc_t1", ConnectorID: "tc_c1", ServerID: "tc_m1",
				PrincipalKind: "user", PrincipalID: "tc_u_a", Status: "error", DurationMS: 20, Error: "boom",
				CreatedAt: time.Date(2026, 1, 10, 1, 30, 0, 0, time.UTC)},
			"tc_i03": {ID: "tc_i03", ToolName: "create_page", ToolID: "tc_t2", ConnectorID: "tc_c2",
				PrincipalKind: "api_key", PrincipalID: "tc_k1", Status: "timeout", DurationMS: 30,
				CreatedAt: time.Date(2026, 1, 10, 2, 0, 0, 0, time.UTC)},
			"tc_i04": {ID: "tc_i04", ToolName: "create_page", ToolID: "tc_t2", ConnectorID: "tc_c2", ServerID: "tc_m1",
				PrincipalKind: "anonymous", Status: "denied", DurationMS: 40,
				CreatedAt: time.Date(2026, 1, 10, 3, 0, 0, 0, time.UTC)},
		}
		for id, w := range want {
			got := byID[id]
			got.CreatedAt = got.CreatedAt.UTC()
			if got != w {
				t.Errorf("%s:\n got %+v\nwant %+v", id, got, w)
			}
		}
	})

	t.Run("refusals", func(t *testing.T) {
		get(t, "tc_u_a", "tc_a", "/api/v1/tool-calls", url.Values{"since": {"2026-01-10T02:00:00Z"}, "until": {"2026-01-10T01:00:00Z"}},
			http.StatusUnprocessableEntity)
		get(t, "tc_u_a", "tc_a", "/api/v1/tool-calls", url.Values{"status": {"failed"}}, http.StatusUnprocessableEntity)
		get(t, "tc_u_a", "tc_a", "/api/v1/tool-calls", url.Values{"since": {"yesterday"}}, http.StatusUnprocessableEntity)
		get(t, "tc_u_none", "tc_a", "/api/v1/tool-calls", nil, http.StatusForbidden)
		get(t, "tc_u_none", "tc_a", "/api/v1/tool-calls/summary", nil, http.StatusForbidden)
		get(t, "tc_u_a", "tc_a", "/api/v1/tool-calls/summary",
			url.Values{"since": {"2025-10-01T00:00:00Z"}, "until": {"2026-01-10T00:00:00Z"}}, http.StatusUnprocessableEntity)
		get(t, "tc_u_a", "tc_a", "/api/v1/tool-calls/summary",
			url.Values{"since": {"2026-01-10T00:00:00Z"}, "until": {"2026-01-10T00:00:00Z"}}, http.StatusUnprocessableEntity)
	})

	summary := func(t *testing.T, user, org string, q url.Values) toolCallsSummary {
		t.Helper()
		var s toolCallsSummary
		if err := json.Unmarshal(get(t, user, org, "/api/v1/tool-calls/summary", q, http.StatusOK), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Run("summary", func(t *testing.T) {
		window := url.Values{"since": {"2026-01-10T00:00:00Z"}, "until": {"2026-01-11T00:00:00Z"}}
		got := summary(t, "tc_u_a", "tc_a", window)
		want := toolCallsSummary{Since: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC), Until: time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
			Total: 6, Failed: 3, ByStatus: toolCallStatusCounts{Success: 3, Error: 1, Timeout: 1, Denied: 1}}
		got.Since, got.Until = got.Since.UTC(), got.Until.UTC()
		if got != want {
			t.Errorf("A: got %+v, want %+v", got, want)
		}
		got = summary(t, "tc_u_b", "tc_b", window)
		if got.Total != 3 || got.Failed != 1 || got.ByStatus != (toolCallStatusCounts{Success: 2, Error: 1}) {
			t.Errorf("B: got %+v, want 3 calls, 1 failed", got)
		}
		// The default window is the seven days to now, where the seed has
		// nothing.
		got = summary(t, "tc_u_a", "tc_a", nil)
		if got.Total != 0 || got.Until.Sub(got.Since) != 7*24*time.Hour || time.Since(got.Until) > time.Minute {
			t.Errorf("default window: got %+v", got)
		}
	})
}

// openAppStore migrates the database and opens both pools with the app
// pool under the row-level security role, as serve does.
func openAppStore(t *testing.T, dsn string, log *slog.Logger) *store.Store {
	t.Helper()
	ctx := context.Background()
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
	return st
}
