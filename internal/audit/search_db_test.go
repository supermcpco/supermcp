package audit_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/supermcpco/supermcp/internal/audit"
)

// TestListSearches checks the q filter: what it finds, what it must not
// find (payload and diff, another tenant's events), and that it combines
// with the other filters and survives an event whose meta the database
// cannot turn into text.
func TestListSearches(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db, "", "_other")
	w := audit.NewWriter(db, testLog(), audit.Options{})
	defer w.Close()

	org, other := s.orgs[0], s.orgs[1]
	seeded := []audit.Event{
		{OrgID: org, Category: audit.CategoryAdmin, Action: "connector.created", Outcome: audit.Success,
			ActorKind: "user", ActorID: "u_ada", ActorDisplay: "ada@example.com",
			TargetKind: "connector", TargetID: "c_github", TargetDisplay: "GitHub",
			Diff:    audit.Changes(nil, map[string]any{"name": "okapi"}),
			Payload: map[string]any{"input": map[string]any{"text": "zebrafish"}},
			Meta:    map[string]any{"reason": "quarterly review", "count": 7}},
		{OrgID: org, Category: audit.CategoryAuth, Action: "session.create", Outcome: audit.Success,
			ActorKind: "user", ActorID: "u_bob",
			Meta: map[string]any{"method": "saml", "provider": "Okta West", "groups": []any{"eng", map[string]any{"nested": "heron"}}}},
		{OrgID: org, Category: audit.CategoryTool, Action: "tool.invoke", Outcome: audit.Denied,
			ActorKind: "user", ActorID: "u_bob",
			Payload: map[string]any{"output": "narwhal"}},
		// A NUL in a meta string is written as \u0000, which Postgres
		// refuses to turn into text. The index must not refuse the event
		// for it, and the rest of meta is still searched.
		{OrgID: org, Category: audit.CategoryAdmin, Action: "member.invited", Outcome: audit.Success,
			ActorKind: "user", ActorID: "u_ada",
			Meta: map[string]any{"reason": "nul\x00here", "other": "flamingo"}},
		// The neighbouring tenant carries the same words.
		{OrgID: other, Category: audit.CategoryAdmin, Action: "connector.created", Outcome: audit.Success,
			ActorKind: "user", ActorID: "u_eve", Meta: map[string]any{"reason": "quarterly review", "only": "pelican"}},
	}
	for _, e := range seeded {
		emitSync(ctx, t, w, e)
	}
	s.bounds(ctx) // record the range so cleanup can find it again
	r := &audit.Reader{DB: db}

	all := []string{"member.invited", "tool.invoke", "session.create", "connector.created"}
	cases := []struct {
		name string
		q    audit.Query
		want []string
	}{
		{name: "the whole action name", q: audit.Query{Search: "connector.created"}, want: []string{"connector.created"}},
		{name: "one part of the action name", q: audit.Query{Search: "connector"}, want: []string{"connector.created"}},
		{name: "a meta string value", q: audit.Query{Search: "quarterly"}, want: []string{"connector.created"}},
		{name: "a nested meta string, any case", q: audit.Query{Search: "HERON"}, want: []string{"session.create"}},
		{name: "a quoted phrase", q: audit.Query{Search: `"quarterly review"`}, want: []string{"connector.created"}},
		{name: "a phrase out of order", q: audit.Query{Search: `"review quarterly"`}, want: []string{}},
		{name: "the actor's email", q: audit.Query{Search: "ada@example.com"}, want: []string{"connector.created"}},
		{name: "the target's name", q: audit.Query{Search: "github"}, want: []string{"connector.created"}},
		{name: "or", q: audit.Query{Search: "okta or quarterly"}, want: []string{"session.create", "connector.created"}},
		{name: "every word must match", q: audit.Query{Search: "okta quarterly"}, want: []string{}},
		{name: "an excluded word", q: audit.Query{Search: "u_bob -narwhal -saml"}, want: []string{"tool.invoke"}},
		{name: "combined with another filter", q: audit.Query{Search: "u_bob", Outcome: audit.Denied}, want: []string{"tool.invoke"}},
		{name: "payload content is not searched", q: audit.Query{Search: "zebrafish"}, want: []string{}},
		{name: "payload content is not searched, whatever the key", q: audit.Query{Search: "narwhal"}, want: []string{}},
		{name: "diff content is not searched", q: audit.Query{Search: "okapi"}, want: []string{}},
		{name: "meta keys and numbers are not searched", q: audit.Query{Search: "reason or 7"}, want: []string{}},
		{name: "another tenant's meta is not found", q: audit.Query{Search: "pelican"}, want: []string{}},
		{name: "text with no words matches nothing", q: audit.Query{Search: "!!!"}, want: []string{}},
		{name: "blank is no search", q: audit.Query{Search: "  \t "}, want: all},
		{name: "an event whose meta holds a NUL is written and found by its action",
			q: audit.Query{Search: "member.invited"}, want: []string{"member.invited"}},
		{name: "an event whose meta holds a NUL is found by the rest of its meta",
			q: audit.Query{Search: "flamingo"}, want: []string{"member.invited"}},
		{name: "and by the string that held the NUL",
			q: audit.Query{Search: "nul here"}, want: []string{"member.invited"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.q.OrgID = org
			got, err := r.List(ctx, tc.q)
			if err != nil {
				t.Fatalf("listing %+v failed: %v", tc.q, err)
			}
			actions := []string{}
			for _, rec := range got {
				actions = append(actions, rec.Action)
			}
			if strings.Join(actions, ", ") != strings.Join(tc.want, ", ") {
				t.Errorf("searching %q returned, newest first:\n  [%s]\nwanted:\n  [%s]",
					tc.q.Search, strings.Join(actions, ", "), strings.Join(tc.want, ", "))
			}
		})
	}

	t.Run("the other tenant finds its own event", func(t *testing.T) {
		got, err := r.List(ctx, audit.Query{OrgID: other, Search: "quarterly"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].ActorID != "u_eve" {
			t.Errorf("the other tenant searching its own words got %+v; want its one event", got)
		}
	})

	t.Run("the search function answers nothing without a workspace", func(t *testing.T) {
		// audit_search runs as its owner, past row-level security, so it
		// takes the workspace from the same setting the policy reads. With
		// none set, as a caller that skipped tenant.Tx would have it, it
		// must find nothing, not everything.
		var n int
		err := pgx.BeginFunc(ctx, db.App, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM audit_search('quarterly', '', '', '', '', '', NULL, NULL, 0, 100)`).Scan(&n)
		})
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("audit_search with no workspace set found %d events", n)
		}
	})

	t.Run("a search pages like the list", func(t *testing.T) {
		q := audit.Query{OrgID: org, Search: "u_bob or u_ada", Limit: 2}
		first, err := r.List(ctx, q)
		if err != nil || len(first) != 2 {
			t.Fatalf("first page: %d records, %v; want 2", len(first), err)
		}
		q.AfterSeq = first[1].Seq
		rest, err := r.List(ctx, q)
		if err != nil || len(rest) != 2 {
			t.Fatalf("second page: %d records, %v; want 2", len(rest), err)
		}
		if rest[0].Seq >= first[1].Seq {
			t.Errorf("the second page starts at seq %d, not below %d", rest[0].Seq, first[1].Seq)
		}
	})

	lo, hi := s.bounds(ctx)
	if res, err := r.Verify(ctx, lo, hi); err != nil || !res.Valid {
		t.Errorf("the chain does not verify with the search index in place: %+v, %v", res, err)
	}
}

// TestSearchReadsTheIndex checks, as the application role and with the
// exact statement List sends, that a search reaches audit_events_search_idx.
// Under the table's forced row-level security a text match written as a
// condition of the list cannot use the index (@@ is not leakproof), and a
// search reads every event the workspace has; this is what failed before
// the search moved into the audit_search function. The function's own
// plan is not in EXPLAIN's output, so auto_explain reports it as a notice,
// which needs a superuser to load; without one the test skips.
func TestSearchReadsTheIndex(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db)
	w := audit.NewWriter(db, testLog(), audit.Options{Buffer: 4096})
	defer w.Close()
	// Enough of the workspace's events that reading them all costs more
	// than reading the index, and statistics that say so.
	for i := range 2000 {
		w.Emit(ctx, audit.Event{OrgID: s.org(), Category: audit.CategoryAdmin, Action: "connector.updated",
			Outcome: audit.Success, ActorKind: "user", ActorID: fmt.Sprintf("u_%d", i), Meta: map[string]any{"reason": "routine"}})
	}
	w.Emit(ctx, audit.Event{OrgID: s.org(), Category: audit.CategoryAdmin, Action: "connector.created",
		Outcome: audit.Success, ActorKind: "user", ActorID: "u_plan", Meta: map[string]any{"reason": "quarterly"}})
	if err := w.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	s.bounds(ctx)
	maintExec(ctx, t, db, `ANALYZE audit_events`)

	var notices []string
	cfg, err := pgx.ParseConfig(ownDatabase(ctx, t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) { notices = append(notices, n.Message) }
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `LOAD 'auto_explain'`); err != nil {
		t.Skipf("auto_explain cannot be loaded here (it needs a superuser), so the function's plan cannot be read: %v", err)
	}
	for _, set := range []string{
		`SET auto_explain.log_min_duration = 0`, `SET auto_explain.log_nested_statements = on`,
		`SET auto_explain.log_level = notice`, `SET client_min_messages = notice`,
		// The rest of the table is small enough to read whole.
		`SET enable_seqscan = off`,
		`SET ROLE supermcp_app`,
	} {
		if _, err := conn.Exec(ctx, set); err != nil {
			t.Fatalf("%s: %v", set, err)
		}
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_org', $1, true)`, s.org()); err != nil {
		t.Fatal(err)
	}
	notices = nil
	rows, err := tx.Query(ctx, audit.ListSearchSQL,
		s.org(), "quarterly", "", "", "", "", "", (*time.Time)(nil), (*time.Time)(nil), int64(0), 100)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for rows.Next() {
		n++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("the search found %d events as the application role, want 1", n)
	}
	plans := strings.Join(notices, "\n")
	var inner string
	for _, p := range notices {
		if strings.Contains(p, "websearch_to_tsquery") {
			inner = p
		}
	}
	if inner == "" {
		t.Fatalf("auto_explain reported no plan for the search inside audit_search; it reported:\n%s", plans)
	}
	if !strings.Contains(inner, "audit_events_search_idx") {
		t.Errorf("the search inside audit_search does not read audit_events_search_idx:\n%s", inner)
	}
	for _, p := range notices {
		if strings.Contains(p, "Filter: (audit_search_document") {
			t.Errorf("a plan tests every event's document instead of reading the index:\n%s", p)
		}
	}
}
