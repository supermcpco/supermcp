package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// A call held for approval, on a server that can ask the person behind
// the client about it. The upstream is never reached in any of these: a
// held call does not run, whatever the answer.

// asker is an MCP client that can answer elicitation/create, and
// remembers what it was asked.
type asker struct {
	mu     sync.Mutex
	asked  []*sdk.ElicitParams
	answer func(ctx context.Context) (*sdk.ElicitResult, error)
}

func (a *asker) client() *sdk.Client {
	return sdk.NewClient(&sdk.Implementation{Name: "elicit-e2e", Version: "1"}, &sdk.ClientOptions{
		ElicitationHandler: func(ctx context.Context, req *sdk.ElicitRequest) (*sdk.ElicitResult, error) {
			a.mu.Lock()
			a.asked = append(a.asked, req.Params)
			a.mu.Unlock()
			return a.answer(ctx)
		},
	})
}

func (a *asker) questions() []*sdk.ElicitParams {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.asked)
}

type approvalWire struct {
	ID              string     `json:"id"`
	State           string     `json:"state"`
	Reason          string     `json:"reason"`
	AcknowledgedAt  *time.Time `json:"acknowledgedAt"`
	Acknowledgement string     `json:"acknowledgement"`
}

// heldFixture is the tool fixture with a policy that holds every call to
// fake_get_item.
func heldFixture(t *testing.T, opts harnessOptions) *toolFixture {
	t.Helper()
	f := newToolFixtureWith(t, opts)
	if code := f.h.do(t, http.MethodPost, "/api/v1/approval-policies", map[string]any{
		"name": "Ask before fake_get_item", "trigger": "tool", "toolName": "fake_get_item",
	}, nil); code != http.StatusCreated {
		t.Fatalf("create approval policy: %d", code)
	}
	return f
}

func (f *toolFixture) approval(t *testing.T, id string) approvalWire {
	t.Helper()
	var r approvalWire
	if code := f.h.do(t, http.MethodGet, "/api/v1/approvals/"+id, nil, &r); code != 200 {
		t.Fatalf("read approval %s: %d", id, code)
	}
	return r
}

// held makes the call and returns the result and the request it raised.
func held(t *testing.T, sess *sdk.ClientSession, args map[string]any) (*sdk.CallToolResult, string) {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &sdk.CallToolParams{Name: "fake_get_item", Arguments: args})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	var notice struct {
		RequestID    string `json:"approvalRequestId"`
		State        string `json:"state"`
		Acknowledged bool   `json:"acknowledged"`
	}
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &notice); err != nil || notice.RequestID == "" {
		t.Fatalf("the call was not held: %s %+v", b, res.Content)
	}
	return res, notice.RequestID
}

func resultText(r *sdk.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// A client that can be asked is asked, and its confirmation is on the
// request for the approver to read. The question carries neither the
// arguments nor the credential.
func TestHeldCallIsConfirmedFromTheClient(t *testing.T) {
	f := heldFixture(t, harnessOptions{})
	f.setSessions(t, "stateful")
	a := &asker{answer: func(context.Context) (*sdk.ElicitResult, error) {
		return &sdk.ElicitResult{Action: "accept", Content: map[string]any{"confirm": true, "note": "Needed for the\u202e quarterly count"}}, nil
	}}
	sess := f.connectMCP(t, a.client())

	res, id := held(t, sess, map[string]any{"id": "order-7731-private"})
	if !res.IsError || !strings.Contains(resultText(res), "confirmed that they asked") {
		t.Errorf("the result after confirming: %q", resultText(res))
	}
	if b, _ := json.Marshal(res.StructuredContent); !strings.Contains(string(b), `"acknowledged":true`) {
		t.Errorf("the notice does not say the call was confirmed: %s", b)
	}

	qs := a.questions()
	if len(qs) != 1 {
		t.Fatalf("the client was asked %d times, want once", len(qs))
	}
	q, _ := json.Marshal(qs[0])
	for _, leak := range []string{"order-7731-private", "secret-value", "FAKE_KEY"} {
		if strings.Contains(string(q), leak) {
			t.Errorf("the question carries %q: %s", leak, q)
		}
	}
	if !strings.Contains(qs[0].Message, "fake_get_item") || !strings.Contains(qs[0].Message, id) {
		t.Errorf("the question does not name the tool and the request: %q", qs[0].Message)
	}

	got := f.approval(t, id)
	if got.State != "pending" || got.AcknowledgedAt == nil || got.Acknowledgement != "Needed for the quarterly count" {
		t.Errorf("the request after confirming: %+v; want pending, confirmed, with the note", got)
	}
	if *f.calls != 0 {
		t.Errorf("the upstream was called %d times for a held call", *f.calls)
	}

	// The same call again joins the same request, which has been asked
	// about already.
	if _, again := held(t, sess, map[string]any{"id": "order-7731-private"}); again != id {
		t.Fatalf("the repeated call raised %s, want %s", again, id)
	}
	if n := len(a.questions()); n != 1 {
		t.Errorf("the client was asked again about a confirmed request (%d questions)", n)
	}
}

// Declining the question withdraws the request.
func TestHeldCallDeclinedFromTheClientIsWithdrawn(t *testing.T) {
	for _, action := range []string{"decline"} {
		t.Run(action, func(t *testing.T) {
			f := heldFixture(t, harnessOptions{})
			f.setSessions(t, "stateful")
			a := &asker{answer: func(context.Context) (*sdk.ElicitResult, error) {
				return &sdk.ElicitResult{Action: action}, nil
			}}
			sess := f.connectMCP(t, a.client())

			res, id := held(t, sess, map[string]any{"id": "1"})
			if !strings.Contains(resultText(res), "withdrawn") {
				t.Errorf("the result after declining: %q", resultText(res))
			}
			if got := f.approval(t, id); got.State != "cancelled" || got.AcknowledgedAt != nil {
				t.Errorf("the request after declining: %+v; want cancelled and unconfirmed", got)
			}
			var found bool
			for _, e := range f.h.auditEvents(t, context.Background(), f.admin.Org.ID) {
				if e.Action == "approval.cancel" && e.TargetID == id && e.Meta["via"] == "elicitation" {
					found = true
				}
			}
			if !found {
				t.Error("withdrawing from the client left nothing on the audit trail")
			}
		})
	}
}

// Where the server cannot ask, or nobody answers, the call is held exactly
// as it was before the question existed.
func TestHeldCallIsUnchangedWhereNobodyCanBeAsked(t *testing.T) {
	cases := []struct {
		name     string
		sessions string
		canAsk   bool
		answer   func(ctx context.Context) (*sdk.ElicitResult, error)
		asked    int
	}{
		{name: "a stateless server", sessions: "stateless", canAsk: true, asked: 0},
		{name: "a client that cannot be asked", sessions: "stateful", canAsk: false, asked: 0},
		{name: "a client that does not answer in time", sessions: "stateful", canAsk: true, asked: 1,
			answer: func(ctx context.Context) (*sdk.ElicitResult, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}},
		{name: "a question dismissed", sessions: "stateful", canAsk: true, asked: 1,
			answer: func(context.Context) (*sdk.ElicitResult, error) {
				return &sdk.ElicitResult{Action: "cancel"}, nil
			}},
		{name: "a form submitted without the confirmation", sessions: "stateful", canAsk: true, asked: 1,
			answer: func(context.Context) (*sdk.ElicitResult, error) {
				return &sdk.ElicitResult{Action: "accept", Content: map[string]any{"confirm": false}}, nil
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := heldFixture(t, harnessOptions{elicitTimeout: 300 * time.Millisecond})
			f.setSessions(t, c.sessions)
			a := &asker{answer: c.answer}
			if a.answer == nil {
				a.answer = func(context.Context) (*sdk.ElicitResult, error) {
					return &sdk.ElicitResult{Action: "decline"}, nil
				}
			}
			client := sdk.NewClient(&sdk.Implementation{Name: "plain-e2e", Version: "1"}, nil)
			if c.canAsk {
				client = a.client()
			}
			sess := f.connectMCP(t, client)

			res, id := held(t, sess, map[string]any{"id": "1"})
			if n := len(a.questions()); n != c.asked {
				t.Errorf("the client was asked %d times, want %d", n, c.asked)
			}
			text := resultText(res)
			if !strings.HasPrefix(text, "This call needs a person to approve it") || strings.Contains(text, "confirmed") {
				t.Errorf("the result is not the plain held result: %q", text)
			}
			if got := f.approval(t, id); got.State != "pending" || got.AcknowledgedAt != nil {
				t.Errorf("the request: %+v; want pending and unconfirmed", got)
			}
		})
	}
}

// A replica told to stop does not wait out a question: the call returns
// held, as it would have without one, and the drain is not held up.
func TestDrainCutsAQuestionShort(t *testing.T) {
	f := heldFixture(t, harnessOptions{elicitTimeout: 10 * time.Minute})
	f.setSessions(t, "stateful")
	asked := make(chan struct{})
	a := &asker{answer: func(ctx context.Context) (*sdk.ElicitResult, error) {
		close(asked)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	sess := f.connectMCP(t, a.client())

	done := make(chan *sdk.CallToolResult, 1)
	go func() {
		res, err := sess.CallTool(context.Background(), &sdk.CallToolParams{Name: "fake_get_item", Arguments: map[string]any{"id": "1"}})
		if err != nil {
			t.Errorf("call: %v", err)
		}
		done <- res
	}()
	<-asked
	f.h.deps.MCP.Drain()
	select {
	case res := <-done:
		if res != nil && !strings.HasPrefix(resultText(res), "This call needs a person to approve it") {
			t.Errorf("the result after the drain: %q", resultText(res))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the call was still waiting on its question after the drain")
	}
}
