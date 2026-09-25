package audit_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

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
		// for it: the row is written and found by its other columns.
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
		{name: "an event whose meta cannot be read is written and found by its action",
			q: audit.Query{Search: "member.invited"}, want: []string{"member.invited"}},
		{name: "an event whose meta cannot be read is not found by its meta",
			q: audit.Query{Search: "flamingo"}, want: []string{}},
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

// TestSearchReadsTheIndex checks that the expression the list searches is
// the one migration 00027 indexed. Were they to drift, every search would
// still answer, by reading the organisation's whole stream.
func TestSearchReadsTheIndex(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	var plan strings.Builder
	err := db.Bypass(ctx, "audit search plan", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `EXPLAIN SELECT seq FROM audit_events WHERE `+audit.SearchDocument+
			` @@ websearch_to_tsquery('simple', 'quarterly')`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return err
			}
			plan.WriteString(line + "\n")
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("explaining a search failed: %v", err)
	}
	if !strings.Contains(plan.String(), "audit_events_search_idx") {
		t.Errorf("a search does not read audit_events_search_idx; the plan is:\n%s", plan.String())
	}
}
