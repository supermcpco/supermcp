package governance_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/governance"
	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/store"
)

// What is being checked here is a state machine and a sealed column, and
// neither can be checked against a fake: whether a second decision is
// refused is a property of the statement that writes the first, and
// whether the arguments are readable in the table is a question about the
// table. Requires DATABASE_URL, and skips without it, like the rest.

const (
	alice = "user_alice"
	bob   = "user_bob"
	carol = "user_carol"
)

type approvalFixture struct {
	*fixture
	svc *governance.Approvals
}

func newApprovalFixture(t *testing.T) *approvalFixture {
	t.Helper()
	f := newFixture(t)
	kek, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), "test")
	if err != nil {
		t.Fatal(err)
	}
	return &approvalFixture{fixture: f,
		svc: governance.NewApprovals(f.db, secrets.New(kek, &store.KeyStore{DB: f.db}), uuid.NewString)}
}

// call is a destructive tool call by alice, which is what a policy
// catches by default.
func (f *approvalFixture) call(args map[string]any) governance.CallRef {
	return governance.CallRef{OrgID: f.orgID, ServerID: "srv1", ConnectorID: "con1", ToolID: "tool1",
		ToolName: "refund_payment", Destructive: true, ActorKind: "user", ActorID: alice,
		ActorDisplay: "Alice", Args: args}
}

// policy stores a rule, switched on: a rule nobody enabled would make
// every one of these tests pass for the wrong reason.
func (f *approvalFixture) policy(ctx context.Context, t *testing.T, p governance.ApprovalPolicy) *governance.ApprovalPolicy {
	t.Helper()
	p.Enabled = true
	out, err := f.svc.CreatePolicy(ctx, f.orgID, p)
	if err != nil {
		t.Fatalf("create policy %s: %v", p.Name, err)
	}
	return out
}

// lapse pushes a request's deadline into the past, which is the only
// honest way to test expiry without waiting for it.
func (f *approvalFixture) lapse(ctx context.Context, t *testing.T, id string) {
	t.Helper()
	err := f.db.Bypass(ctx, "test: age an approval request", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE approval_requests SET expires_at = now() - interval '1 minute' WHERE id = $1`, id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *approvalFixture) sealedArgs(ctx context.Context, t *testing.T, id string) []byte {
	t.Helper()
	var raw []byte
	err := f.db.Bypass(ctx, "test: read the sealed column", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT args_enc FROM approval_requests WHERE id = $1`, id).Scan(&raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *approvalFixture) raise(ctx context.Context, t *testing.T, c governance.CallRef) *governance.ApprovalRequest {
	t.Helper()
	out, err := f.svc.Check(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Required {
		t.Fatal("the call ran without anyone agreeing to it")
	}
	return out.ApprovalRequest
}

func (f *approvalFixture) approve(ctx context.Context, t *testing.T, id, by string) *governance.ApprovalRequest {
	t.Helper()
	r, err := f.svc.Decide(ctx, f.orgID, id, governance.Decision{Approve: true, ActorID: by, Reason: "fine"})
	if err != nil {
		t.Fatalf("approve %s: %v", id, err)
	}
	return r
}

// --- the state machine -----------------------------------------------------

// Every transition that must be refused, refused in the place that can
// actually enforce it. Approving your own request is the one that decides
// whether any of this is worth having.
func TestApprovalRefusesTheTransitionsItMust(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	ctx := t.Context()
	f.policy(ctx, t, governance.ApprovalPolicy{Name: "destructive", Trigger: governance.TriggerDestructive})

	t.Run("nobody approves their own request", func(t *testing.T) {
		r := f.raise(ctx, t, f.call(map[string]any{"amount": 1}))
		_, err := f.svc.Decide(ctx, f.orgID, r.ID, governance.Decision{Approve: true, ActorID: alice})
		if !errors.Is(err, governance.ErrSelfDecision) {
			t.Fatalf("alice approved her own request: %v", err)
		}
		// And the request is untouched, not half-decided.
		again, err := f.svc.Get(ctx, f.orgID, r.ID)
		if err != nil || again.State != governance.StatePending {
			t.Fatalf("state after the refused decision: %v %v", again.State, err)
		}
	})

	t.Run("a decision is made once", func(t *testing.T) {
		r := f.raise(ctx, t, f.call(map[string]any{"amount": 2}))
		f.approve(ctx, t, r.ID, bob)
		_, err := f.svc.Decide(ctx, f.orgID, r.ID, governance.Decision{ActorID: carol, Reason: "no"})
		if !errors.Is(err, governance.ErrAlreadyDecided) {
			t.Fatalf("carol overrode bob: %v", err)
		}
	})

	t.Run("an expired request cannot be decided", func(t *testing.T) {
		r := f.raise(ctx, t, f.call(map[string]any{"amount": 3}))
		f.lapse(ctx, t, r.ID)
		_, err := f.svc.Decide(ctx, f.orgID, r.ID, governance.Decision{Approve: true, ActorID: bob, Reason: "late"})
		if !errors.Is(err, governance.ErrRequestExpired) {
			t.Fatalf("a lapsed request was approved: %v", err)
		}
		// Reading it settled it: the record now says expired rather than
		// still waiting for an answer nobody can give.
		after, err := f.svc.Get(ctx, f.orgID, r.ID)
		if err != nil || after.State != governance.StateExpired {
			t.Fatalf("state after the deadline: %v %v", after.State, err)
		}
	})

	t.Run("only the asker withdraws", func(t *testing.T) {
		r := f.raise(ctx, t, f.call(map[string]any{"amount": 4}))
		if _, err := f.svc.Cancel(ctx, f.orgID, r.ID, bob, "not mine"); !errors.Is(err, governance.ErrNotRequester) {
			t.Fatalf("bob withdrew alice's request: %v", err)
		}
		if _, err := f.svc.Cancel(ctx, f.orgID, r.ID, alice, "changed my mind"); err != nil {
			t.Fatalf("alice could not withdraw her own request: %v", err)
		}
		if _, err := f.svc.Cancel(ctx, f.orgID, r.ID, alice, "again"); !errors.Is(err, governance.ErrAlreadyDecided) {
			t.Fatalf("withdrawing twice: %v", err)
		}
	})

	t.Run("a refusal needs a reason", func(t *testing.T) {
		r := f.raise(ctx, t, f.call(map[string]any{"amount": 5}))
		if _, err := f.svc.Decide(ctx, f.orgID, r.ID, governance.Decision{ActorID: bob}); err == nil {
			t.Fatal("a call was refused with no reason on the record")
		}
	})

	t.Run("a request that does not exist", func(t *testing.T) {
		_, err := f.svc.Decide(ctx, f.orgID, "nope", governance.Decision{Approve: true, ActorID: bob})
		if !errors.Is(err, governance.ErrApprovalNotFound) {
			t.Fatalf("deciding nothing: %v", err)
		}
	})
}

// Nobody answered, somebody refused and somebody withdrew are three
// different records, and a caller is told which.
func TestUnansweredRefusedAndWithdrawnAreDifferentStates(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	ctx := t.Context()
	f.policy(ctx, t, governance.ApprovalPolicy{Name: "destructive", Trigger: governance.TriggerDestructive})

	lapsed := f.raise(ctx, t, f.call(map[string]any{"which": "lapsed"}))
	f.lapse(ctx, t, lapsed.ID)
	refused := f.raise(ctx, t, f.call(map[string]any{"which": "refused"}))
	if _, err := f.svc.Decide(ctx, f.orgID, refused.ID, governance.Decision{ActorID: bob, Reason: "wrong account"}); err != nil {
		t.Fatal(err)
	}
	withdrawn := f.raise(ctx, t, f.call(map[string]any{"which": "withdrawn"}))
	if _, err := f.svc.Cancel(ctx, f.orgID, withdrawn.ID, alice, ""); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		id   string
		want governance.State
	}{
		{lapsed.ID, governance.StateExpired},
		{refused.ID, governance.StateRejected},
		{withdrawn.ID, governance.StateCancelled},
	} {
		got, err := f.svc.Get(ctx, f.orgID, tc.id)
		if err != nil {
			t.Fatal(err)
		}
		if got.State != tc.want {
			t.Errorf("request %s is %q, want %q", tc.id, got.State, tc.want)
		}
	}

	// The sweep makes the stored row agree with what readers were told.
	// It runs across tenants, so it may settle other requests too; what
	// matters is that it settles this one and stops.
	if _, err := f.svc.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := f.db.Bypass(ctx, "test: read the stored state", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT state FROM approval_requests WHERE id = $1`, lapsed.ID).Scan(&stored)
	}); err != nil {
		t.Fatal(err)
	}
	if stored != string(governance.StateExpired) {
		t.Errorf("the sweep left the row as %q, want expired", stored)
	}

	// A refused call, asked again exactly as it was, comes back refused
	// rather than queueing the same question a second time.
	out, err := f.svc.Check(ctx, f.call(map[string]any{"which": "refused"}))
	if err != nil {
		t.Fatal(err)
	}
	if !out.Required || out.ApprovalRequest.ID != refused.ID {
		t.Fatalf("a refused call raised a fresh request: %+v", out.ApprovalRequest)
	}
	if !strings.Contains(out.Message, "wrong account") {
		t.Errorf("the model was not told why: %q", out.Message)
	}
}

// --- the arguments ---------------------------------------------------------

// The arguments are the reason the call is worth approving, so they are
// sealed like a credential and not written next to the tool's name.
func TestArgumentsAreSealedAtRestAndComeBackIntact(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	ctx := t.Context()
	f.policy(ctx, t, governance.ApprovalPolicy{Name: "destructive", Trigger: governance.TriggerDestructive})

	args := map[string]any{
		"account": "4111111111111111",
		"amount":  1250.5,
		"note":    "refund for order 9981",
		"nested":  map[string]any{"reference": "PAY-77-SECRET"},
	}
	r := f.raise(ctx, t, f.call(args))

	raw := f.sealedArgs(ctx, t, r.ID)
	for _, secret := range []string{"4111111111111111", "PAY-77-SECRET", "refund for order", "account"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("%q is readable in args_enc", secret)
		}
	}

	opened, err := f.svc.Open(ctx, f.orgID, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Args["account"] != "4111111111111111" || opened.Args["amount"] != 1250.5 {
		t.Fatalf("the arguments did not come back: %#v", opened.Args)
	}
	nested, ok := opened.Args["nested"].(map[string]any)
	if !ok || nested["reference"] != "PAY-77-SECRET" {
		t.Fatalf("the nested argument did not come back: %#v", opened.Args["nested"])
	}

	// Listing the queue does not open anything: an approver asks for one
	// request, and that asking is what gets recorded.
	list, err := f.svc.List(ctx, f.orgID, governance.StatePending, "", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Args != nil {
		t.Fatalf("the queue handed back arguments nobody asked for: %#v", list)
	}
}

// The point of sealing them rather than digesting them: what runs the
// second time is what a person agreed to, not what the model asks for
// once it knows the answer is yes.
func TestReplayRunsTheApprovedArgumentsAndOnlyOnce(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	ctx := t.Context()
	f.policy(ctx, t, governance.ApprovalPolicy{Name: "destructive", Trigger: governance.TriggerDestructive})

	r := f.raise(ctx, t, f.call(map[string]any{"amount": 10.0, "account": "acct_1"}))
	f.approve(ctx, t, r.ID, bob)

	// The model asks again, for ten thousand instead of ten.
	greedy := f.call(map[string]any{"amount": 10000.0, "account": "acct_9", governance.ArgApprovalID: r.ID})
	out, err := f.svc.Check(ctx, greedy)
	if err != nil {
		t.Fatal(err)
	}
	if out.Required {
		t.Fatalf("an approved request would not replay: %s", out.Message)
	}
	if out.Args["amount"] != 10.0 || out.Args["account"] != "acct_1" {
		t.Fatalf("the replay ran the model's arguments, not the approved ones: %#v", out.Args)
	}
	if _, present := out.Args[governance.ArgApprovalID]; present {
		t.Error("the approval argument was passed on to the tool")
	}

	// An approval is good for one call.
	again, err := f.svc.Check(ctx, greedy)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Required || again.ApprovalRequest.State != governance.StateConsumed {
		t.Fatalf("the same approval was spent twice: %+v", again.ApprovalRequest)
	}

	// And it belongs to the person who asked.
	stranger := f.call(map[string]any{"amount": 10.0, governance.ArgApprovalID: r.ID})
	stranger.ActorID = carol
	third, err := f.svc.Check(ctx, stranger)
	if err != nil {
		t.Fatal(err)
	}
	if !third.Required {
		t.Fatal("carol replayed alice's approval")
	}
}

// A model has no way of knowing its first attempt went anywhere, so the
// same call twice is one question, not two.
func TestTheSameCallTwiceJoinsOneQueue(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	ctx := t.Context()
	f.policy(ctx, t, governance.ApprovalPolicy{Name: "destructive", Trigger: governance.TriggerDestructive})

	first := f.raise(ctx, t, f.call(map[string]any{"amount": 7.0, "account": "acct_1"}))
	second := f.raise(ctx, t, f.call(map[string]any{"account": "acct_1", "amount": 7.0}))
	if first.ID != second.ID {
		t.Errorf("the same call queued twice: %s and %s", first.ID, second.ID)
	}
	// A different call is a different question.
	other := f.raise(ctx, t, f.call(map[string]any{"amount": 8.0, "account": "acct_1"}))
	if other.ID == first.ID {
		t.Error("a call for a different amount reused the first request")
	}
	pending, err := f.svc.List(ctx, f.orgID, governance.StatePending, alice, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 {
		t.Errorf("alice has %d requests waiting, want 2", len(pending))
	}
}

// --- policy resolution -----------------------------------------------------

// Four scopes, narrowest wins, and an allow at the narrow end is how a
// broad rule gets narrowed rather than deleted.
func TestPolicyResolutionAcrossTheFourScopes(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	ctx := t.Context()
	c := f.call(map[string]any{"amount": 1.0})

	org := f.policy(ctx, t, governance.ApprovalPolicy{Name: "everything destructive", Trigger: governance.TriggerDestructive})
	if got := f.governing(ctx, t, c); got.ID != org.ID {
		t.Fatalf("the organisation's rule did not govern: %s", got.Name)
	}

	server := f.policy(ctx, t, governance.ApprovalPolicy{Name: "this server", Scope: governance.ScopeServer, ScopeID: "srv1",
		Trigger: governance.TriggerDestructive})
	if got := f.governing(ctx, t, c); got.ID != server.ID {
		t.Fatalf("the server's rule did not beat the organisation's: %s", got.Name)
	}

	conn := f.policy(ctx, t, governance.ApprovalPolicy{Name: "this connector", Scope: governance.ScopeConnector, ScopeID: "con1",
		Trigger: governance.TriggerDestructive})
	if got := f.governing(ctx, t, c); got.ID != conn.ID {
		t.Fatalf("the connector's rule did not beat the server's: %s", got.Name)
	}

	tool := f.policy(ctx, t, governance.ApprovalPolicy{Name: "this tool", Scope: governance.ScopeTool, ScopeID: "tool1",
		Trigger: governance.TriggerDestructive, Effect: governance.EffectAllow})
	if got := f.governing(ctx, t, c); got.ID != tool.ID {
		t.Fatalf("the tool's rule did not beat the connector's: %s", got.Name)
	}
	// The narrowest rule waives the approval, so the call runs.
	out, err := f.svc.Check(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if out.Required {
		t.Fatal("an exemption at the tool did not exempt the tool")
	}

	// A rule hung on something else reaches nothing here.
	f.policy(ctx, t, governance.ApprovalPolicy{Name: "another server", Scope: governance.ScopeServer, ScopeID: "srv-other",
		Trigger: governance.TriggerDestructive})
	if got := f.governing(ctx, t, c); got.ID != tool.ID {
		t.Fatalf("a rule for another server changed the answer: %s", got.Name)
	}

	// Two rules of the same width that disagree: the one that asks for a
	// person wins, because a contradiction should not be resolved in
	// favour of the payment going out.
	f.policy(ctx, t, governance.ApprovalPolicy{Name: "this tool, by name", Scope: governance.ScopeTool, ScopeID: "tool1",
		Trigger: governance.TriggerTool, ToolName: "refund_payment"})
	out, err = f.svc.Check(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Required {
		t.Fatal("two rules disagreed and the call went through")
	}

	// Switching the exemption off leaves the connector's rule governing.
	disabled := *tool
	disabled.Enabled = false
	if _, err := f.svc.UpdatePolicy(ctx, f.orgID, tool.ID, disabled, ""); err != nil {
		t.Fatal(err)
	}
	if got := f.governing(ctx, t, c); got.ID == tool.ID {
		t.Error("a rule that was switched off still governed the call")
	}
	if err := f.svc.DeletePolicy(ctx, f.orgID, "no such policy", ""); !errors.Is(err, governance.ErrPolicyNotFound) {
		t.Errorf("deleting nothing: %v", err)
	}
}

func (f *approvalFixture) governing(ctx context.Context, t *testing.T, c governance.CallRef) *governance.ApprovalPolicy {
	t.Helper()
	p, err := f.svc.Governing(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("no rule governs this call")
	}
	return p
}

// A call nothing reaches runs, and the approval argument never reaches a
// tool even when there is no policy to take it out.
func TestACallNoRuleReachesRuns(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	ctx := t.Context()

	out, err := f.svc.Check(ctx, f.call(map[string]any{"amount": 1.0, governance.ArgApprovalID: ""}))
	if err != nil {
		t.Fatal(err)
	}
	if out.Required {
		t.Fatal("a call with no policy against it needed approval")
	}
	if _, present := out.Args[governance.ArgApprovalID]; present {
		t.Error("the approval argument was passed on to the tool")
	}
}

func TestPolicyRefusesRulesThatCannotMeanAnything(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	ctx := t.Context()

	for _, tc := range []struct {
		name   string
		policy governance.ApprovalPolicy
	}{
		{"no name", governance.ApprovalPolicy{Trigger: governance.TriggerDestructive}},
		{"unknown trigger", governance.ApprovalPolicy{Name: "x", Trigger: "whenever"}},
		{"a named tool with no name", governance.ApprovalPolicy{Name: "x", Trigger: governance.TriggerTool}},
		{"a condition with no conditions", governance.ApprovalPolicy{Name: "x", Trigger: governance.TriggerCondition}},
		{"an unknown operator", governance.ApprovalPolicy{Name: "x", Trigger: governance.TriggerCondition,
			Conditions: []governance.ApprovalCondition{{Arg: "amount", Op: "approximately"}}}},
		{"a scope with nothing in it", governance.ApprovalPolicy{Name: "x", Scope: governance.ScopeConnector,
			Trigger: governance.TriggerDestructive}},
		{"an approval that lasts a second", governance.ApprovalPolicy{Name: "x", Trigger: governance.TriggerDestructive, TTL: 1}},
	} {
		if _, err := f.svc.CreatePolicy(ctx, f.orgID, tc.policy); !errors.Is(err, governance.ErrInvalidPolicy) {
			t.Errorf("%s was accepted: %v", tc.name, err)
		}
	}
}

// A condition policy catches the calls it describes and nothing else.
// This one needs no database: what is under test is the rule, not where
// it is kept.
func TestConditionsMatchTheCallsTheyDescribe(t *testing.T) {
	t.Parallel()
	call := func(args map[string]any) governance.CallRef {
		return governance.CallRef{ServerID: "srv1", ConnectorID: "con1", ToolID: "tool1",
			ToolName: "refund_payment", Destructive: true, Args: args}
	}
	over1000 := governance.ApprovalPolicy{Scope: governance.ScopeOrganization, Trigger: governance.TriggerCondition,
		Conditions: []governance.ApprovalCondition{{Arg: "amount", Op: governance.OpGreaterThan, Value: 1000.0}}}

	for _, tc := range []struct {
		name   string
		policy governance.ApprovalPolicy
		call   governance.CallRef
		want   bool
	}{
		{"over the threshold", over1000, call(map[string]any{"amount": 1000.5}), true},
		{"on the threshold", over1000, call(map[string]any{"amount": 1000.0}), false},
		{"the argument left out", over1000, call(map[string]any{}), false},
		{"the argument is not a number", over1000, call(map[string]any{"amount": "lots"}), false},
		{"every condition has to hold", governance.ApprovalPolicy{Trigger: governance.TriggerCondition,
			Conditions: []governance.ApprovalCondition{
				{Arg: "amount", Op: governance.OpGreaterThan, Value: 100.0},
				{Arg: "currency", Op: governance.OpEquals, Value: "GBP"},
			}}, call(map[string]any{"amount": 500.0, "currency": "USD"}), false},
		{"a nested argument", governance.ApprovalPolicy{Trigger: governance.TriggerCondition,
			Conditions: []governance.ApprovalCondition{{Arg: "order.total", Op: governance.OpGreaterOrEqual, Value: 10.0}}},
			call(map[string]any{"order": map[string]any{"total": 10.0}}), true},
		{"one of a list", governance.ApprovalPolicy{Trigger: governance.TriggerCondition,
			Conditions: []governance.ApprovalCondition{{Arg: "region", Op: governance.OpIn, Value: []any{"eu", "uk"}}}},
			call(map[string]any{"region": "uk"}), true},
		{"a prefix", governance.ApprovalPolicy{Trigger: governance.TriggerCondition,
			Conditions: []governance.ApprovalCondition{{Arg: "table", Op: governance.OpPrefix, Value: "prod_"}}},
			call(map[string]any{"table": "prod_payments"}), true},
		{"an argument that is there at all", governance.ApprovalPolicy{Trigger: governance.TriggerCondition,
			Conditions: []governance.ApprovalCondition{{Arg: "force", Op: governance.OpExists}}},
			call(map[string]any{"force": false}), true},
		{"a destructive tool", governance.ApprovalPolicy{Trigger: governance.TriggerDestructive},
			call(map[string]any{}), true},
		{"a tool that only reads", governance.ApprovalPolicy{Trigger: governance.TriggerDestructive},
			governance.CallRef{ToolID: "tool1", Destructive: false}, false},
		{"a tool by name", governance.ApprovalPolicy{Trigger: governance.TriggerTool, ToolName: "refund_payment"},
			call(map[string]any{}), true},
		{"another tool by name", governance.ApprovalPolicy{Trigger: governance.TriggerTool, ToolName: "list_payments"},
			call(map[string]any{}), false},
		{"a rule hung on another connector", governance.ApprovalPolicy{Scope: governance.ScopeConnector, ScopeID: "con2",
			Trigger: governance.TriggerDestructive}, call(map[string]any{}), false},
	} {
		if got := tc.policy.Matches(tc.call); got != tc.want {
			t.Errorf("%s: matched=%v, want %v", tc.name, got, tc.want)
		}
	}
}

// An approved request stays usable for a while after it is approved: an
// answer given a minute before the question went stale is still an
// answer, and a model that polls once a minute should not miss it.
func TestApprovalIsGoodForItsOwnWindow(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	ctx := t.Context()
	f.policy(ctx, t, governance.ApprovalPolicy{Name: "destructive", Trigger: governance.TriggerDestructive, TTL: 3600})

	r := f.raise(ctx, t, f.call(map[string]any{"amount": 1.0}))
	approved := f.approve(ctx, t, r.ID, bob)
	if !approved.ExpiresAt.After(r.ExpiresAt) {
		t.Errorf("approving did not move the deadline: %s then %s", r.ExpiresAt, approved.ExpiresAt)
	}
	if approved.DecidedBy != bob || approved.DecidedAt == nil {
		t.Errorf("the decision did not record who made it: %+v", approved)
	}
	if time.Since(*approved.DecidedAt) > time.Minute {
		t.Errorf("the decision was stamped %s ago", time.Since(*approved.DecidedAt))
	}
}

// Nothing here is visible to another tenant, which is the property the
// whole table depends on and the one it would be easiest to lose.
func TestApprovalsAreInvisibleToAnotherOrganisation(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	ctx := t.Context()
	other := newApprovalFixture(t)
	f.policy(ctx, t, governance.ApprovalPolicy{Name: "destructive", Trigger: governance.TriggerDestructive})

	r := f.raise(ctx, t, f.call(map[string]any{"amount": 1.0}))
	if _, err := other.svc.Get(ctx, other.orgID, r.ID); !errors.Is(err, governance.ErrApprovalNotFound) {
		t.Fatalf("another organisation read the request: %v", err)
	}
	list, err := other.svc.List(ctx, other.orgID, "", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("another organisation saw %d requests", len(list))
	}
	policies, err := other.svc.Policies(ctx, other.orgID)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 0 {
		t.Fatalf("another organisation saw %d rules", len(policies))
	}
}

// A requester confirming their own request is recorded beside it, and
// changes nothing about who may decide it: it is not an approval.
func TestAcknowledgementIsARecordNotADecision(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	ctx := t.Context()
	f.policy(ctx, t, governance.ApprovalPolicy{Name: "destructive", Trigger: governance.TriggerDestructive})
	r := f.raise(ctx, t, f.call(map[string]any{"amount": 12}))

	if _, err := f.svc.Acknowledge(ctx, f.orgID, r.ID, bob, "not mine"); !errors.Is(err, governance.ErrNotRequester) {
		t.Fatalf("bob confirmed alice's request: %v", err)
	}
	long := strings.Repeat("é", governance.MaxAcknowledgement+20)
	got, err := f.svc.Acknowledge(ctx, f.orgID, r.ID, alice, "  "+long+"  ")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != governance.StatePending || got.AcknowledgedAt == nil {
		t.Fatalf("after confirming: state %s, acknowledged %v; want pending and a time", got.State, got.AcknowledgedAt)
	}
	if n := len([]rune(got.Acknowledgement)); n != governance.MaxAcknowledgement {
		t.Errorf("the note kept %d characters, want %d", n, governance.MaxAcknowledgement)
	}
	// The first confirmation stands.
	again, err := f.svc.Acknowledge(ctx, f.orgID, r.ID, alice, "second thoughts")
	if err != nil {
		t.Fatal(err)
	}
	if again.Acknowledgement != got.Acknowledgement || !again.AcknowledgedAt.Equal(*got.AcknowledgedAt) {
		t.Errorf("a second confirmation replaced the first: %q", again.Acknowledgement)
	}
	// The asker still cannot decide it; someone else still can.
	if _, err := f.svc.Decide(ctx, f.orgID, r.ID, governance.Decision{Approve: true, ActorID: alice}); !errors.Is(err, governance.ErrSelfDecision) {
		t.Fatalf("alice approved her own confirmed request: %v", err)
	}
	decided, err := f.svc.Decide(ctx, f.orgID, r.ID, governance.Decision{Approve: true, ActorID: bob})
	if err != nil {
		t.Fatal(err)
	}
	if decided.Acknowledgement != got.Acknowledgement {
		t.Errorf("the decision lost the confirmation: %q", decided.Acknowledgement)
	}
	if _, err := f.svc.Acknowledge(ctx, f.orgID, r.ID, alice, ""); !errors.Is(err, governance.ErrNotPending) {
		t.Errorf("confirming a decided request: %v", err)
	}
}

// Whether a server has anything to follow up depends on the rules that
// ask for a person and could reach it, and on no others.
func TestPolicyReachesTheServersItCouldHold(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	ctx := t.Context()
	reaches := func() bool {
		t.Helper()
		ok, err := f.svc.Reaches(ctx, f.orgID, "srv1", []string{"con1"}, []string{"tool1", "tool2"})
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if reaches() {
		t.Fatal("a server is reached with no rules at all")
	}
	f.policy(ctx, t, governance.ApprovalPolicy{Name: "another server", Scope: governance.ScopeServer, ScopeID: "srv2",
		Trigger: governance.TriggerDestructive})
	f.policy(ctx, t, governance.ApprovalPolicy{Name: "exempt", Scope: governance.ScopeConnector, ScopeID: "con1",
		Trigger: governance.TriggerDestructive, Effect: governance.EffectAllow})
	if reaches() {
		t.Error("a rule for another server, or one that only exempts, reaches this one")
	}
	f.policy(ctx, t, governance.ApprovalPolicy{Name: "one tool", Scope: governance.ScopeTool, ScopeID: "tool2",
		Trigger: governance.TriggerDestructive})
	if !reaches() {
		t.Error("a rule on one of the server's tools does not reach it")
	}
}

// What a requester writes reaches an approver without anything that can
// disguise it or anything the detectors know to be sensitive.
func TestRequesterTextIsCleanedBeforeAnApproverReadsIt(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, in, want string
		limit          int
	}{
		{"plain", "  Needed for the audit  ", "Needed for the audit", 100},
		{"line breaks become spaces", "one\ntwo\tthree", "one two three", 100},
		{"bidirectional override and zero width removed", "pay\u202eevil\u200b bill\x1b[31m", "payevil bill[31m", 100},
		{"a card number is masked", "card 4111 1111 1111 1111 please", "card <redacted:payment_card> please", 100},
		{"cut to the limit", "abcdef", "abc", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := governance.RequesterText(tc.in, tc.limit); got != tc.want {
				t.Errorf("RequesterText(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Declining the question about a call does not undo a confirmation that
// reached the request first.
func TestWithdrawLeavesAConfirmedRequest(t *testing.T) {
	t.Parallel()
	f := newApprovalFixture(t)
	ctx := t.Context()
	f.policy(ctx, t, governance.ApprovalPolicy{Name: "destructive", Trigger: governance.TriggerDestructive})
	r := f.raise(ctx, t, f.call(map[string]any{"amount": 3}))
	if _, err := f.svc.Acknowledge(ctx, f.orgID, r.ID, alice, "yes"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Withdraw(ctx, f.orgID, r.ID, alice, "no"); !errors.Is(err, governance.ErrConfirmed) {
		t.Fatalf("withdrawing a confirmed request: %v", err)
	}
	other := f.raise(ctx, t, f.call(map[string]any{"amount": 4}))
	got, err := f.svc.Withdraw(ctx, f.orgID, other.ID, alice, "not\u202e me")
	if err != nil || got.State != governance.StateCancelled || got.Reason != "not me" {
		t.Fatalf("withdrawing an unconfirmed request: %+v %v", got, err)
	}
}
