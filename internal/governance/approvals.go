package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/dlp"
	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// Approvals: a person agreeing to a tool call before it runs.
//
// A model holding a valid key can already do everything its role allows,
// which for a destructive tool means it can refund a payment on its own
// say-so. A policy here puts a person between the authorisation decision
// and the engine, for the calls an organisation has said are worth it.
//
// Nothing waits. A tool call cannot sit open for an hour, so a gated call
// returns immediately with the id of the request it raised and is told to
// ask again once someone has answered. The arguments are sealed when the
// request is written, and the replay runs those rather than whatever the
// model sends the second time: otherwise approving a refund of £10 would
// authorise a refund of £10,000.

// State is how far a request has got. Expiry and cancellation are states
// rather than absences: a request nobody answered, one that was refused
// and one the asker withdrew are three different histories, and a record
// that cannot tell them apart answers none of the questions asked of it.
type State string

// The states a request moves through. Only pending has successors.
const (
	StatePending   State = "pending"
	StateApproved  State = "approved"
	StateRejected  State = "rejected"
	StateExpired   State = "expired"
	StateCancelled State = "cancelled"
	StateConsumed  State = "consumed"
)

// Scope is where a policy hangs. The most specific one that matches a
// call governs it.
type Scope string

// The four scopes, narrowest last.
const (
	ScopeOrganization Scope = "organization"
	ScopeServer       Scope = "server"
	ScopeConnector    Scope = "connector"
	ScopeTool         Scope = "tool"
)

// Trigger is what makes a policy match a call.
type Trigger string

// The three triggers: every tool that changes state, one tool by name, or
// a call whose arguments match a condition.
const (
	TriggerDestructive Trigger = "destructive"
	TriggerTool        Trigger = "tool"
	TriggerCondition   Trigger = "condition"
)

// Effect is what the governing policy does.
type Effect string

// Require asks for a person; allow exempts. Allow exists so a broad rule
// can be narrowed: without it the only way to change an organisation-wide
// policy would be to delete it.
const (
	EffectRequire Effect = "require"
	EffectAllow   Effect = "allow"
)

// The comparisons a condition can make. Deliberately no regular
// expression: a pattern supplied by an administrator and run against
// arguments supplied by a model is a denial of service waiting for
// someone to write a nested quantifier.
const (
	OpEquals         = "eq"
	OpNotEquals      = "ne"
	OpGreaterThan    = "gt"
	OpGreaterOrEqual = "gte"
	OpLessThan       = "lt"
	OpLessOrEqual    = "lte"
	OpContains       = "contains"
	OpPrefix         = "prefix"
	OpIn             = "in"
	OpExists         = "exists"
	OpAbsent         = "absent"
)

// ArgApprovalID is the argument a model repeats its call with once a
// request has been answered. It is stripped before the call runs, so a
// tool never sees it.
const ArgApprovalID = "_approval"

// defaultTTL is how long a request lives when no policy says otherwise.
const defaultTTL = time.Hour

// maxPendingPerTool bounds how many unanswered requests one caller can
// pile up against one tool. A model that retries with fresh arguments
// would otherwise fill both the queue and the table, and a queue nobody
// can work through protects nothing.
const maxPendingPerTool = 20

// Errors a caller has to tell apart. Each one is a different sentence on
// a screen and a different HTTP status.
var (
	ErrApprovalNotFound = errors.New("approval request not found")
	ErrPolicyNotFound   = errors.New("approval policy not found")
	ErrAlreadyDecided   = errors.New("this request has already been answered")
	ErrRequestExpired   = errors.New("this request expired before anyone answered it")
	ErrSelfDecision     = errors.New("an approval cannot be decided by the person who asked for it")
	ErrNotRequester     = errors.New("only the person who asked for a request may withdraw it")
	ErrTooManyPending   = errors.New("too many requests are already waiting for this tool")
	ErrInvalidPolicy    = errors.New("this approval policy is not usable as written")
	ErrNotPending       = errors.New("this request is no longer waiting for an answer")
	ErrConfirmed        = errors.New("the person who asked for this request has confirmed it")
)

// maxReason bounds a withdrawal's reason, as the API does.
const maxReason = 2000

// RequesterText is what is kept of text the person asking for a call
// wrote, which an approver will read: control and format characters
// (bidirectional overrides, zero-width joiners, escapes) removed, line
// breaks and tabs turned into spaces, anything the data-loss detectors
// recognise masked, and at most limit characters. It is the requester's
// word and is shown as such, never as part of the product's own text.
func RequesterText(s string, limit int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteRune(' ')
		case unicode.In(r, unicode.Cc, unicode.Cf):
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if masked, _, err := dlp.Apply(out, dlp.ActionMask, dlp.Options{}); err == nil {
		if m, ok := masked.(string); ok {
			out = m
		}
	}
	if r := []rune(out); len(r) > limit {
		out = strings.TrimSpace(string(r[:limit]))
	}
	return out
}

// MaxAcknowledgement bounds the note a requester adds when they confirm.
// It is read by an approver, not stored for its own sake.
const MaxAcknowledgement = 500

// ApprovalCondition compares one argument of the call.
type ApprovalCondition struct {
	// Arg is a dotted path into the arguments, so a nested field can be
	// named: "order.total".
	Arg   string `json:"arg"`
	Op    string `json:"op"`
	Value any    `json:"value,omitempty"`
}

// ApprovalPolicy is a standing rule about which calls need a person.
type ApprovalPolicy struct {
	ID         string              `json:"id"`
	OrgID      string              `json:"-"`
	Name       string              `json:"name"`
	Scope      Scope               `json:"scope"`
	ScopeID    string              `json:"scopeId,omitempty"`
	Trigger    Trigger             `json:"trigger"`
	ToolName   string              `json:"toolName,omitempty"`
	Conditions []ApprovalCondition `json:"conditions,omitempty"`
	Effect     Effect              `json:"effect"`
	TTL        int                 `json:"ttlSeconds"`
	Enabled    bool                `json:"enabled"`
	CreatedBy  string              `json:"createdBy,omitempty"`
	CreatedAt  time.Time           `json:"createdAt"`
	UpdatedAt  time.Time           `json:"updatedAt"`
}

// ApprovalRequest is one call waiting on a person, or the record of one that was
// answered. Args is filled only where the caller has been allowed to open
// them; everywhere else it is nil, because the arguments are the part
// worth sealing.
type ApprovalRequest struct {
	ID               string         `json:"id"`
	OrgID            string         `json:"-"`
	PolicyID         string         `json:"policyId,omitempty"`
	PolicyName       string         `json:"policyName,omitempty"`
	ServerID         string         `json:"serverId,omitempty"`
	ConnectorID      string         `json:"connectorId,omitempty"`
	ToolID           string         `json:"toolId"`
	ToolName         string         `json:"toolName"`
	RequestedBy      string         `json:"requestedBy"`
	RequesterKind    string         `json:"requesterKind"`
	RequesterDisplay string         `json:"requesterDisplay,omitempty"`
	State            State          `json:"state"`
	CreatedAt        time.Time      `json:"createdAt"`
	ExpiresAt        time.Time      `json:"expiresAt"`
	TTL              int            `json:"ttlSeconds"`
	DecidedBy        string         `json:"decidedBy,omitempty"`
	DecidedAt        *time.Time     `json:"decidedAt,omitempty"`
	CancelledAt      *time.Time     `json:"cancelledAt,omitempty"`
	ConsumedAt       *time.Time     `json:"consumedAt,omitempty"`
	Reason           string         `json:"reason,omitempty"`
	AcknowledgedAt   *time.Time     `json:"acknowledgedAt,omitempty" doc:"When the person who asked confirmed, from their MCP client, that they meant the call. It is not an approval"`
	Acknowledgement  string         `json:"acknowledgement,omitempty" doc:"The note they added for the approver when they confirmed"`
	Args             map[string]any `json:"args,omitempty"`
}

// CallRef is the call an approval is about. It is plain fields rather
// than the executor's own types so that this package stays below the one
// that runs tool calls.
type CallRef struct {
	OrgID       string
	ServerID    string
	ConnectorID string
	ToolID      string
	ToolName    string
	// Destructive is the tool's annotation, which is the default trigger:
	// what an organisation buys this feature for is the calls that change
	// something.
	Destructive  bool
	ActorKind    string
	ActorID      string
	ActorDisplay string
	Args         map[string]any
}

// Outcome is what the executor does next.
//
// Required means the call must not run. Args are the arguments to run
// when it may: the ones that were approved on a replay, and otherwise the
// caller's own with the approval argument taken out.
type Outcome struct {
	Required        bool
	Args            map[string]any
	ApprovalRequest *ApprovalRequest
	Message         string
}

// Notice is the machine-readable half of a refusal. A model is told what
// to do in prose, but a client that wants to show a link to the request
// needs the id without parsing English.
type Notice struct {
	Status         string    `json:"status"`
	RequestID      string    `json:"approvalRequestId"`
	State          State     `json:"state"`
	Tool           string    `json:"tool"`
	ApprovalPolicy string    `json:"policy,omitempty"`
	ExpiresAt      time.Time `json:"expiresAt"`
	Reason         string    `json:"reason,omitempty"`
	RetryWith      string    `json:"retryWith,omitempty"`
	// Acknowledged is set when the person behind the client confirmed the
	// call when asked. It is not an approval.
	Acknowledged bool `json:"acknowledged,omitempty"`
}

// Decision is one person's answer.
type Decision struct {
	Approve      bool
	ActorID      string
	ActorDisplay string
	Reason       string
}

// Approvals reads and writes the rules, the requests and the answers.
type Approvals struct {
	DB     *tenant.DB
	Sealer *secrets.Sealer
	NewID  func() string
	// Audit records the transitions that happen on the invocation path —
	// raising a request, spending one, letting one expire. The ones that
	// happen over HTTP are recorded by the handler that serves them, which
	// knows the address and the session the answer came from.
	Audit audit.Sink
	// Revisions records each change to a policy beside the change, in the
	// same transaction. Nil records nothing.
	Revisions *Service
}

// NewApprovals builds the service.
func NewApprovals(db *tenant.DB, sealer *secrets.Sealer, newID func() string) *Approvals {
	return &Approvals{DB: db, Sealer: sealer, NewID: newID}
}

// Check decides whether a call may run now.
//
// It is the whole of what the executor needs: a call that needs nobody
// comes straight back, a replay comes back with the arguments that were
// approved, and anything else comes back as a refusal naming the request
// a person has to answer.
func (a *Approvals) Check(ctx context.Context, c CallRef) (*Outcome, error) {
	claimID, args := splitApprovalID(c.Args)
	c.Args = args

	// An explicit id is answered on its own terms even when no policy
	// matches today: the request was raised under the rules as they stood,
	// and a rule deleted in the meantime should not silently turn an
	// approval into something that never happened.
	if claimID != "" {
		return a.claim(ctx, c, claimID)
	}
	policy, err := a.Governing(ctx, c)
	if err != nil {
		return nil, err
	}
	if policy == nil || policy.Effect == EffectAllow {
		return &Outcome{Args: args}, nil
	}
	req, err := a.Raise(ctx, c, policy)
	if err != nil {
		return nil, err
	}
	return a.waiting(req), nil
}

// Governing returns the policy that decides this call, or nil when no
// rule reaches it. The policy is returned whatever its effect, so that a
// screen can explain why a call did not need anyone.
func (a *Approvals) Governing(ctx context.Context, c CallRef) (*ApprovalPolicy, error) {
	if c.OrgID == "" {
		return nil, tenant.ErrNoOrg
	}
	var list []ApprovalPolicy
	err := a.DB.Tx(tenant.WithOrg(ctx, c.OrgID), func(tx pgx.Tx) error {
		var err error
		list, err = scanPolicies(ctx, tx, `SELECT `+policyColumns+` FROM approval_policies
			WHERE enabled AND (scope_kind = 'organization'
				OR (scope_kind = 'server' AND scope_id = $1)
				OR (scope_kind = 'connector' AND scope_id = $2)
				OR (scope_kind = 'tool' AND scope_id = $3))
			ORDER BY created_at, id`, c.ServerID, c.ConnectorID, c.ToolID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("read approval policies: %w", err)
	}
	var best *ApprovalPolicy
	for i := range list {
		p := &list[i]
		if !p.Matches(c) {
			continue
		}
		// Narrower beats broader; at the same width a rule that asks for a
		// person beats one that waives them, because two rules that
		// disagree about the same call are a mistake and the safe reading
		// of a mistake is the one that stops the payment.
		switch {
		case best == nil, p.rank() > best.rank():
			best = p
		case p.rank() == best.rank() && p.Effect == EffectRequire && best.Effect == EffectAllow:
			best = p
		}
	}
	return best, nil
}

// Reaches reports whether any enabled rule that asks for a person could
// hold a call on this server: one for the whole organisation, for the
// server, or for one of the connectors or tools it serves. It is what
// decides whether a server lists the tools for following a request up;
// a server no rule reaches has nothing to follow up.
func (a *Approvals) Reaches(ctx context.Context, orgID, serverID string, connectorIDs, toolIDs []string) (bool, error) {
	if orgID == "" {
		return false, tenant.ErrNoOrg
	}
	var reaches bool
	err := a.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM approval_policies
			WHERE enabled AND effect = 'require' AND (scope_kind = 'organization'
				OR (scope_kind = 'server' AND scope_id = $1)
				OR (scope_kind = 'connector' AND scope_id = ANY($2))
				OR (scope_kind = 'tool' AND scope_id = ANY($3))))`, serverID, connectorIDs, toolIDs).Scan(&reaches)
	})
	if err != nil {
		return false, fmt.Errorf("read approval policies: %w", err)
	}
	return reaches, nil
}

// Raise records a call that needs a person, and seals its arguments.
//
// A model that calls the same tool the same way twice gets the same
// request back rather than a second one: it has no way of knowing its
// first attempt went anywhere, and a queue with the same question in it
// forty times is a queue nobody reads. A call somebody has already
// refused comes back refused for as long as that answer stands, which is
// what stops a retry loop from wearing the approver down.
func (a *Approvals) Raise(ctx context.Context, c CallRef, policy *ApprovalPolicy) (*ApprovalRequest, error) {
	switch {
	case c.OrgID == "":
		return nil, tenant.ErrNoOrg
	case c.ToolID == "":
		return nil, errors.New("an approval request needs the tool it is about")
	case c.ActorID == "":
		return nil, errors.New("an approval request needs to name who asked for it")
	}
	args, err := canonical(c.Args)
	if err != nil {
		return nil, err
	}
	ttl := defaultTTL
	var policyID, policyName string
	if policy != nil {
		policyID, policyName = policy.ID, policy.Name
		if policy.TTL > 0 {
			ttl = time.Duration(policy.TTL) * time.Second
		}
	}
	id := a.NewID()
	orgCtx := tenant.WithOrg(ctx, c.OrgID)
	// Sealed before the transaction opens: minting an organisation's first
	// data key is itself a database write, and nesting that inside this
	// one would hold a connection while it happens.
	sealed, err := a.Sealer.Seal(orgCtx, secrets.ScopeOrg(c.OrgID), args, argsAAD(c.OrgID, id))
	if err != nil {
		return nil, fmt.Errorf("seal approval arguments: %w", err)
	}

	var out *ApprovalRequest
	err = a.DB.Tx(orgCtx, func(tx pgx.Tx) error {
		// One asker, one tool, one queue. Two concurrent calls with the
		// same arguments would otherwise both find nothing and both
		// insert, and the second approval is one nobody meant to give.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext(current_org() || '/' || $2 || '/' || $3))`,
			approvalLockClass, c.ToolID, c.ActorID); err != nil {
			return fmt.Errorf("lock approval queue: %w", err)
		}
		existing, pending, err := a.sameCall(ctx, tx, c, args)
		if err != nil {
			return err
		}
		if existing != nil {
			out = existing
			return nil
		}
		if pending >= maxPendingPerTool {
			return ErrTooManyPending
		}
		display := c.ActorDisplay
		if display == "" {
			// An approver reading "01a0cced-262c-…" cannot tell who asked.
			// A service account has no email, so the name it was given is
			// what stands in for one.
			display = nameOf(ctx, tx, c.ActorKind, c.ActorID)
		}
		out, err = scanRequest(tx.QueryRow(ctx, `INSERT INTO approval_requests
			(id, organization_id, policy_id, policy_name, server_id, connector_id, tool_id, tool_name,
			 requested_by, requester_kind, requester_display, args_enc, state, expires_at, ttl_seconds)
			VALUES ($1, current_org(), NULLIF($2,''), $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending',
			        now() + make_interval(secs => $12), $12)
			RETURNING `+requestColumns,
			id, policyID, policyName, c.ServerID, c.ConnectorID, c.ToolID, c.ToolName,
			c.ActorID, orDefault(c.ActorKind, "user"), display, sealed, int(ttl.Seconds())), nil)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrTooManyPending) {
			return nil, err
		}
		return nil, fmt.Errorf("raise approval request: %w", err)
	}
	if out.ID == id {
		a.emit(ctx, out, "approval.request", audit.Success, map[string]any{"policy": policyName})
	}
	return out, nil
}

// Decide records one person's answer. The person may not be the one who
// asked: that is checked in the statement that writes the answer, not
// before it, so two approvers racing on the same request cannot both win
// and a decider who edits their own id into the request body gets
// nothing.
func (a *Approvals) Decide(ctx context.Context, orgID, id string, d Decision) (*ApprovalRequest, error) {
	if d.ActorID == "" {
		return nil, errors.New("a decision needs to name who made it")
	}
	if !d.Approve && strings.TrimSpace(d.Reason) == "" {
		return nil, errors.New("a refusal needs a reason")
	}
	state := StateRejected
	if d.Approve {
		state = StateApproved
	}
	var out *ApprovalRequest
	err := a.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		out, err = scanRequest(tx.QueryRow(ctx, `UPDATE approval_requests
			SET state = $2, decided_by = $3, decided_at = now(), reason = $4,
			    expires_at = CASE WHEN $2 = 'approved' THEN now() + make_interval(secs => ttl_seconds) ELSE expires_at END
			WHERE id = $1 AND state = 'pending' AND expires_at > now() AND requested_by <> $3
			RETURNING `+requestColumns, id, string(state), d.ActorID, strings.TrimSpace(d.Reason)), nil)
		if errors.Is(err, pgx.ErrNoRows) {
			return a.refuseDecision(ctx, tx, id, d.ActorID)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Cancel withdraws a request. Only the asker may: a person who wanted the
// request gone and could not answer it themselves would otherwise have a
// way to make an awkward question disappear. The reason is the asker's
// own text, and is kept as RequesterText leaves it.
func (a *Approvals) Cancel(ctx context.Context, orgID, id, actorID, reason string) (*ApprovalRequest, error) {
	return a.cancel(ctx, orgID, id, actorID, reason, false)
}

// Withdraw is Cancel for a request its asker has not confirmed. It is what
// declining the question about a held call does: a confirmation that
// reached the request first, from another answer to the same question,
// stands.
func (a *Approvals) Withdraw(ctx context.Context, orgID, id, actorID, reason string) (*ApprovalRequest, error) {
	return a.cancel(ctx, orgID, id, actorID, reason, true)
}

func (a *Approvals) cancel(ctx context.Context, orgID, id, actorID, reason string, unconfirmedOnly bool) (*ApprovalRequest, error) {
	if actorID == "" {
		return nil, errors.New("withdrawing a request needs to name who did it")
	}
	var out *ApprovalRequest
	err := a.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		out, err = scanRequest(tx.QueryRow(ctx, `UPDATE approval_requests
			SET state = 'cancelled', cancelled_at = now(), reason = $3
			WHERE id = $1 AND state = 'pending' AND requested_by = $2 AND (NOT $4 OR acknowledged_at IS NULL)
			RETURNING `+requestColumns, id, actorID, RequesterText(reason, maxReason), unconfirmedOnly), nil)
		if errors.Is(err, pgx.ErrNoRows) {
			current, ferr := a.read(ctx, tx, id)
			switch {
			case ferr != nil:
				return ferr
			case current.RequestedBy != actorID:
				return ErrNotRequester
			case unconfirmedOnly && current.State == StatePending && current.AcknowledgedAt != nil:
				return ErrConfirmed
			case current.State == StateExpired:
				return ErrRequestExpired
			default:
				return ErrAlreadyDecided
			}
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Acknowledge records that the person who asked for a request confirmed
// it, with the note they left for the approver. It does not approve
// anything: the request stays pending, and only someone else can decide
// it. Only the asker may, and only once, while the request is waiting.
func (a *Approvals) Acknowledge(ctx context.Context, orgID, id, actorID, note string) (*ApprovalRequest, error) {
	if actorID == "" {
		return nil, errors.New("confirming a request needs to name who did it")
	}
	note = RequesterText(note, MaxAcknowledgement)
	var out *ApprovalRequest
	wrote := false
	err := a.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		out, err = scanRequest(tx.QueryRow(ctx, `UPDATE approval_requests
			SET acknowledged_at = now(), acknowledgement = $3
			WHERE id = $1 AND requested_by = $2 AND state = 'pending' AND expires_at > now() AND acknowledged_at IS NULL
			RETURNING `+requestColumns, id, actorID, note), nil)
		if errors.Is(err, pgx.ErrNoRows) {
			current, ferr := a.read(ctx, tx, id)
			switch {
			case ferr != nil:
				return ferr
			case current.RequestedBy != actorID:
				return ErrNotRequester
			case current.State == StatePending:
				// Already confirmed: the first confirmation stands.
				out = current
				return nil
			default:
				return ErrNotPending
			}
		}
		wrote = err == nil
		return err
	})
	if err != nil {
		return nil, err
	}
	if wrote {
		a.emit(ctx, out, "approval.acknowledge", audit.Success, map[string]any{"withNote": note != ""})
	}
	return out, nil
}

// Get reads one request without opening its arguments.
func (a *Approvals) Get(ctx context.Context, orgID, id string) (*ApprovalRequest, error) {
	var out *ApprovalRequest
	err := a.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		out, err = a.read(ctx, tx, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Open reads one request with its arguments. It is separate from Get
// because opening the arguments is the privileged half: they are what was
// sealed, and an approver is the only person with a reason to see them.
func (a *Approvals) Open(ctx context.Context, orgID, id string) (*ApprovalRequest, error) {
	var out *ApprovalRequest
	var sealed []byte
	err := a.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		out, err = scanRequest(tx.QueryRow(ctx, `SELECT `+requestColumns+`, args_enc FROM approval_requests WHERE id = $1`, id), &sealed)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrApprovalNotFound
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	out.Args, err = a.open(ctx, orgID, id, sealed)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// List reads the requests in a state, newest first. An empty state reads
// every state; requester narrows it to one person's own.
func (a *Approvals) List(ctx context.Context, orgID string, state State, requester string, limit int) ([]ApprovalRequest, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	out := []ApprovalRequest{}
	err := a.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+requestColumns+` FROM approval_requests
			WHERE ($1 = '' OR `+effectiveState+` = $1) AND ($2 = '' OR requested_by = $2)
			ORDER BY created_at DESC LIMIT $3`, string(state), requester, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRequest(rows, nil)
			if err != nil {
				return err
			}
			out = append(out, *r)
		}
		return rows.Err()
	})
	return out, err
}

// Sweep settles the requests nobody answered, across every organisation.
// A read already reports an unanswered request as expired, so this exists
// to make the stored row agree with what everyone has been told, and to
// give the expiry a time of its own in the audit stream.
func (a *Approvals) Sweep(ctx context.Context) (int, error) {
	var n int64
	err := a.DB.Bypass(ctx, "approvals: expire unanswered requests", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE approval_requests SET state = 'expired'
			WHERE state = 'pending' AND expires_at <= now()`)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("expire approval requests: %w", err)
	}
	return int(n), nil
}

// --- policies --------------------------------------------------------------

// Policies reads an organisation's rules, broadest first.
func (a *Approvals) Policies(ctx context.Context, orgID string) ([]ApprovalPolicy, error) {
	var out []ApprovalPolicy
	err := a.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		out, err = scanPolicies(ctx, tx, `SELECT `+policyColumns+` FROM approval_policies ORDER BY scope_kind, name, id`)
		return err
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []ApprovalPolicy{}
	}
	return out, nil
}

// GetPolicy reads one rule.
func (a *Approvals) GetPolicy(ctx context.Context, orgID, id string) (*ApprovalPolicy, error) {
	var out *ApprovalPolicy
	err := a.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		list, err := scanPolicies(ctx, tx, `SELECT `+policyColumns+` FROM approval_policies WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			return ErrPolicyNotFound
		}
		out = &list[0]
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CreatePolicy stores a new rule. The creator is p.CreatedBy, which is
// also who the revision names.
func (a *Approvals) CreatePolicy(ctx context.Context, orgID string, p ApprovalPolicy) (*ApprovalPolicy, error) {
	if err := p.normalise(); err != nil {
		return nil, err
	}
	p.ID, p.OrgID = a.NewID(), orgID
	err := a.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		if err := insertApprovalPolicy(ctx, tx, &p); err != nil {
			return err
		}
		return a.recordPolicy(ctx, tx, p, ActionCreate, audit.Created(p), p.CreatedBy)
	})
	if err != nil {
		return nil, fmt.Errorf("create approval policy: %w", err)
	}
	return &p, nil
}

// UpdatePolicy replaces a rule wholesale. A rule read, edited on a screen
// and sent back is the whole rule, so a partial update here would leave
// fields nobody could clear.
func (a *Approvals) UpdatePolicy(ctx context.Context, orgID, id string, p ApprovalPolicy, actorID string) (*ApprovalPolicy, error) {
	if err := p.normalise(); err != nil {
		return nil, err
	}
	p.ID, p.OrgID = id, orgID
	err := a.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		before, err := lockApprovalPolicy(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := updateApprovalPolicy(ctx, tx, &p); err != nil {
			return err
		}
		if err := a.baselinePolicy(ctx, tx, before); err != nil {
			return err
		}
		return a.recordPolicy(ctx, tx, p, ActionUpdate, audit.Changes(before, p), actorID)
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// RestorePolicy puts a rule back the way a revision recorded it, through
// the statements an edit uses. A rule that has since been deleted is
// recreated under its old id and with its old creator. The requests it
// raised before the delete do not point at it again: the delete set their
// policy to nothing, and they keep the rule's name as it was.
//
// It returns the rule as restored and the one it replaced, read under the
// row lock; the second is nil when the rule was recreated.
func (a *Approvals) RestorePolicy(ctx context.Context, orgID, id string, p ApprovalPolicy, actorID string) (*ApprovalPolicy, *ApprovalPolicy, error) {
	if err := p.normalise(); err != nil {
		return nil, nil, err
	}
	p.ID, p.OrgID = id, orgID
	var replaced *ApprovalPolicy
	err := a.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		before, err := lockApprovalPolicy(ctx, tx, id)
		switch {
		case errors.Is(err, ErrPolicyNotFound):
			if err := insertApprovalPolicy(ctx, tx, &p); err != nil {
				return err
			}
			return a.recordPolicy(ctx, tx, p, ActionCreate, audit.Created(p), actorID)
		case err != nil:
			return err
		}
		if err := updateApprovalPolicy(ctx, tx, &p); err != nil {
			return err
		}
		if err := a.baselinePolicy(ctx, tx, before); err != nil {
			return err
		}
		if err := a.recordPolicy(ctx, tx, p, ActionUpdate, audit.Changes(before, p), actorID); err != nil {
			return err
		}
		replaced = &before
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return &p, replaced, nil
}

// DeletePolicy removes a rule. The requests it raised stay: what someone
// approved last week is not undone by changing the rule this week. Its
// history stays too, so it can be restored.
func (a *Approvals) DeletePolicy(ctx context.Context, orgID, id, actorID string) error {
	return a.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		before, err := lockApprovalPolicy(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM approval_policies WHERE id = $1`, id); err != nil {
			return err
		}
		if err := a.baselinePolicy(ctx, tx, before); err != nil {
			return err
		}
		return a.recordPolicy(ctx, tx, before, ActionDelete, audit.Deleted(before), actorID)
	})
}

// lockApprovalPolicy reads a rule inside the writing transaction and holds
// its row, so the before a revision records is the one the write replaced.
func lockApprovalPolicy(ctx context.Context, tx pgx.Tx, id string) (ApprovalPolicy, error) {
	list, err := scanPolicies(ctx, tx, `SELECT `+policyColumns+` FROM approval_policies WHERE id = $1 FOR UPDATE`, id)
	if err != nil {
		return ApprovalPolicy{}, err
	}
	if len(list) == 0 {
		return ApprovalPolicy{}, ErrPolicyNotFound
	}
	return list[0], nil
}

func insertApprovalPolicy(ctx context.Context, tx pgx.Tx, p *ApprovalPolicy) error {
	conditions, err := json.Marshal(p.Conditions)
	if err != nil {
		return fmt.Errorf("encode policy conditions: %w", err)
	}
	return tx.QueryRow(ctx, `INSERT INTO approval_policies
		(id, organization_id, name, scope_kind, scope_id, trigger_kind, tool_name, conditions,
		 effect, ttl_seconds, enabled, created_by)
		VALUES ($1, current_org(), $2, $3, $4, $5, $6, $7, $8, $9, $10, NULLIF($11,''))
		RETURNING created_at, updated_at`,
		p.ID, p.Name, string(p.Scope), p.ScopeID, string(p.Trigger), p.ToolName,
		conditionsFor(*p, conditions), string(p.Effect), p.TTL, p.Enabled, p.CreatedBy).
		Scan(&p.CreatedAt, &p.UpdatedAt)
}

func updateApprovalPolicy(ctx context.Context, tx pgx.Tx, p *ApprovalPolicy) error {
	conditions, err := json.Marshal(p.Conditions)
	if err != nil {
		return fmt.Errorf("encode policy conditions: %w", err)
	}
	err = tx.QueryRow(ctx, `UPDATE approval_policies
		SET name = $2, scope_kind = $3, scope_id = $4, trigger_kind = $5, tool_name = $6,
		    conditions = $7, effect = $8, ttl_seconds = $9, enabled = $10, updated_at = now()
		WHERE id = $1 RETURNING created_at, updated_at, COALESCE(created_by,'')`,
		p.ID, p.Name, string(p.Scope), p.ScopeID, string(p.Trigger), p.ToolName,
		conditionsFor(*p, conditions), string(p.Effect), p.TTL, p.Enabled).
		Scan(&p.CreatedAt, &p.UpdatedAt, &p.CreatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPolicyNotFound
	}
	return err
}

// baselinePolicy records a rule as it stood before its first recorded
// change, for one written before rules had a history, so that version can
// be put back too.
func (a *Approvals) baselinePolicy(ctx context.Context, tx pgx.Tx, before ApprovalPolicy) error {
	if a.Revisions == nil {
		return nil
	}
	return a.Revisions.RecordBaseline(ctx, tx, string(KindApprovalPolicy), before.ID, before)
}

// recordPolicy writes the rule's revision when a history is configured.
func (a *Approvals) recordPolicy(ctx context.Context, tx pgx.Tx, p ApprovalPolicy, action string, diff *audit.Diff, actorID string) error {
	if a.Revisions == nil {
		return nil
	}
	return a.Revisions.RecordRevision(ctx, tx, Revision{Kind: KindApprovalPolicy, EntityID: p.ID, Action: action,
		Entity: p, Diff: diff, ActorID: actorID})
}

// Matches reports whether this policy reaches the call at all, before its
// effect is considered.
func (p *ApprovalPolicy) Matches(c CallRef) bool {
	if !p.scopeMatches(c) {
		return false
	}
	switch p.Trigger {
	case TriggerDestructive:
		return c.Destructive
	case TriggerTool:
		return p.ToolName != "" && p.ToolName == c.ToolName
	case TriggerCondition:
		if len(p.Conditions) == 0 {
			return false
		}
		for _, cond := range p.Conditions {
			if !cond.matches(c.Args) {
				return false
			}
		}
		return true
	}
	return false
}

// Notice renders the refusal for a client that would rather read fields
// than a sentence.
func (o *Outcome) Notice() *Notice {
	if o == nil || o.ApprovalRequest == nil {
		return nil
	}
	r := o.ApprovalRequest
	n := &Notice{Status: "approval_" + string(r.State), RequestID: r.ID, State: r.State,
		Tool: r.ToolName, ApprovalPolicy: r.PolicyName, ExpiresAt: r.ExpiresAt, Reason: r.Reason}
	if r.State == StatePending || r.State == StateApproved {
		n.RetryWith = ArgApprovalID
	}
	return n
}

// --- internals -------------------------------------------------------------

// approvalLockClass namespaces the advisory lock that serialises one
// caller's requests against one tool. The two-argument form has its own
// key space, so it cannot collide with the revision sequence or the audit
// chain.
const approvalLockClass int32 = 0x4150 // "AP"

// nameOf answers "who asked for this" when the caller could not say. It
// is best effort: a name nobody can find is better left empty than
// guessed at, and the identifier is always shown beside it.
func nameOf(ctx context.Context, tx pgx.Tx, kind, id string) string {
	var name string
	var err error
	switch kind {
	case "service_account":
		err = tx.QueryRow(ctx, `SELECT name FROM service_accounts WHERE id = $1`, id).Scan(&name)
	case "user", "":
		err = tx.QueryRow(ctx, `SELECT COALESCE(NULLIF(name,''), email) FROM users WHERE id = $1`, id).Scan(&name)
	}
	if err != nil {
		return ""
	}
	return name
}

// effectiveState is what a reader is told. A pending request past its
// deadline is expired whether or not the sweep has been round yet;
// reporting it as pending would invite someone to answer a question that
// is closed.
const effectiveState = `CASE WHEN state = 'pending' AND expires_at <= now() THEN 'expired' ELSE state END`

const requestColumns = `id, organization_id, COALESCE(policy_id,''), policy_name, server_id, connector_id, tool_id, tool_name,
	requested_by, requester_kind, requester_display, ` + effectiveState + `, created_at, expires_at, ttl_seconds,
	COALESCE(decided_by,''), decided_at, cancelled_at, consumed_at, reason, acknowledged_at, acknowledgement`

const policyColumns = `id, name, scope_kind, scope_id, trigger_kind, tool_name, conditions, effect,
	ttl_seconds, enabled, COALESCE(created_by,''), created_at, updated_at`

// claim spends an approved request, or explains why it cannot.
//
// The state moves in the statement that reads the arguments, so an
// approval is good exactly once: two calls racing to replay the same
// refund give one result and one refusal, not two refunds.
func (a *Approvals) claim(ctx context.Context, c CallRef, id string) (*Outcome, error) {
	var req *ApprovalRequest
	var sealed []byte
	err := a.DB.Tx(tenant.WithOrg(ctx, c.OrgID), func(tx pgx.Tx) error {
		var err error
		req, err = scanRequest(tx.QueryRow(ctx, `UPDATE approval_requests
			SET state = 'consumed', consumed_at = now()
			WHERE id = $1 AND requested_by = $2 AND state = 'approved' AND expires_at > now()
			RETURNING `+requestColumns+`, args_enc`, id, c.ActorID), &sealed)
		if errors.Is(err, pgx.ErrNoRows) {
			req, err = a.read(ctx, tx, id)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(sealed) == 0 {
		return a.waiting(req), nil
	}
	args, err := a.open(ctx, c.OrgID, id, sealed)
	if err != nil {
		return nil, err
	}
	a.emit(ctx, req, "approval.replay", audit.Success, map[string]any{"decidedBy": req.DecidedBy})
	// The approved arguments, not the ones the model sent this time. The
	// second call is a request to run what a person agreed to; if the
	// model has changed its mind it can ask again and be asked again.
	return &Outcome{Args: args, ApprovalRequest: req}, nil
}

// waiting turns a request the call cannot use into the refusal the caller
// reads. Every branch says what happened and whether asking again is
// worth anything, because the reader is a model deciding what to do next.
func (a *Approvals) waiting(r *ApprovalRequest) *Outcome {
	o := &Outcome{Required: true, ApprovalRequest: r, Args: map[string]any{}}
	switch r.State {
	case StatePending:
		o.Message = fmt.Sprintf("This call needs a person to approve it before it can run. "+
			"Request %s is waiting, and lapses at %s. Do not repeat the call as it stands: "+
			"once someone has approved it, call this tool again with %q set to %q, and the arguments "+
			"that were approved are the ones that will run.",
			r.ID, r.ExpiresAt.UTC().Format(time.RFC3339), ArgApprovalID, r.ID)
	case StateApproved:
		o.Message = fmt.Sprintf("Request %s has been approved but could not be used. "+
			"It may belong to another caller, or it may have lapsed at %s.",
			r.ID, r.ExpiresAt.UTC().Format(time.RFC3339))
	case StateRejected:
		o.Message = fmt.Sprintf("Request %s was refused: %s. Do not try this call again; "+
			"tell the person you are working for that it was declined.", r.ID, orDefault(r.Reason, "no reason given"))
	case StateExpired:
		o.Message = fmt.Sprintf("Request %s lapsed at %s without an answer. Nobody refused it and nobody agreed to it.",
			r.ID, r.ExpiresAt.UTC().Format(time.RFC3339))
	case StateCancelled:
		o.Message = fmt.Sprintf("Request %s was withdrawn before anyone answered it.", r.ID)
	case StateConsumed:
		o.Message = fmt.Sprintf("Request %s has already been used. An approval is good for one call.", r.ID)
	default:
		o.Message = fmt.Sprintf("Request %s cannot be used.", r.ID)
	}
	return o
}

// sameCall looks for the answer this call already has: the request still
// waiting for it, or the refusal that still stands. It also counts what
// this caller has queued against this tool, because the count is only
// worth taking while the queue is locked.
func (a *Approvals) sameCall(ctx context.Context, tx pgx.Tx, c CallRef, args []byte) (*ApprovalRequest, int, error) {
	rows, err := tx.Query(ctx, `SELECT `+requestColumns+`, args_enc FROM approval_requests
		WHERE tool_id = $1 AND requested_by = $2
		  AND ((state = 'pending' AND expires_at > now())
		    OR (state = 'rejected' AND decided_at > now() - make_interval(secs => ttl_seconds)))
		ORDER BY created_at DESC LIMIT $3`, c.ToolID, c.ActorID, maxPendingPerTool)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	type candidate struct {
		req    *ApprovalRequest
		sealed []byte
	}
	var found []candidate
	pending := 0
	for rows.Next() {
		var sealed []byte
		r, err := scanRequest(rows, &sealed)
		if err != nil {
			return nil, 0, err
		}
		if r.State == StatePending {
			pending++
		}
		found = append(found, candidate{r, sealed})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	// Compared by opening each candidate rather than by a digest stored
	// beside the ciphertext: a digest of an amount or a customer id is a
	// confirmable guess, and would give back to anyone holding this table
	// most of what sealing the column was for.
	for _, cand := range found {
		prev, err := a.open(ctx, c.OrgID, cand.req.ID, cand.sealed)
		if err != nil {
			return nil, 0, err
		}
		same, err := canonical(prev)
		if err != nil {
			return nil, 0, err
		}
		if string(same) == string(args) {
			return cand.req, pending, nil
		}
	}
	return nil, pending, nil
}

// refuseDecision explains a decision that wrote nothing. It runs in the
// same transaction as the attempt, so what it reports is the state that
// refused the write rather than one a concurrent decision has since
// moved on from. An unanswered request past its deadline is settled here
// as well: the reader has just been told it expired, and the record
// should say so too.
func (a *Approvals) refuseDecision(ctx context.Context, tx pgx.Tx, id, actorID string) error {
	current, err := a.read(ctx, tx, id)
	if err != nil {
		return err
	}
	switch {
	case current.RequestedBy == actorID:
		return ErrSelfDecision
	case current.State == StateExpired:
		if _, err := tx.Exec(ctx, `UPDATE approval_requests SET state = 'expired' WHERE id = $1 AND state = 'pending'`, id); err != nil {
			return err
		}
		return ErrRequestExpired
	default:
		return ErrAlreadyDecided
	}
}

func (a *Approvals) read(ctx context.Context, tx pgx.Tx, id string) (*ApprovalRequest, error) {
	r, err := scanRequest(tx.QueryRow(ctx, `SELECT `+requestColumns+` FROM approval_requests WHERE id = $1`, id), nil)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrApprovalNotFound
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (a *Approvals) open(ctx context.Context, orgID, id string, sealed []byte) (map[string]any, error) {
	plain, err := a.Sealer.Open(tenant.WithOrg(ctx, orgID), sealed, argsAAD(orgID, id))
	if err != nil {
		return nil, fmt.Errorf("open approval arguments: %w", err)
	}
	args := map[string]any{}
	if err := json.Unmarshal(plain, &args); err != nil {
		return nil, fmt.Errorf("decode approval arguments: %w", err)
	}
	return args, nil
}

func (a *Approvals) emit(ctx context.Context, r *ApprovalRequest, action, outcome string, meta map[string]any) {
	if a.Audit == nil || r == nil {
		return
	}
	if meta == nil {
		meta = map[string]any{}
	}
	meta["request"] = r.ID
	a.Audit.Emit(ctx, audit.Event{OrgID: r.OrgID, Category: audit.CategoryGovernan, Action: action, Outcome: outcome,
		ActorKind: r.RequesterKind, ActorID: r.RequestedBy, ActorDisplay: r.RequesterDisplay,
		TargetKind: "tool", TargetID: r.ToolID, TargetDisplay: r.ToolName, Meta: meta})
}

// argsAAD binds a sealed argument list to the row that holds it, so a
// ciphertext moved to a cheaper request fails to open.
func argsAAD(orgID, id string) secrets.AAD {
	return secrets.AAD{Table: "approval_requests", Column: "args_enc", RowID: id, OrgID: orgID}
}

func (p *ApprovalPolicy) scopeMatches(c CallRef) bool {
	switch p.Scope {
	// An empty scope reads as the whole organisation, which is what
	// storing the rule would have made it.
	case ScopeOrganization, "":
		return true
	case ScopeServer:
		return p.ScopeID != "" && p.ScopeID == c.ServerID
	case ScopeConnector:
		return p.ScopeID != "" && p.ScopeID == c.ConnectorID
	case ScopeTool:
		return p.ScopeID != "" && p.ScopeID == c.ToolID
	}
	return false
}

// rank orders the scopes by how few calls they reach.
func (p *ApprovalPolicy) rank() int {
	switch p.Scope {
	case ScopeTool:
		return 3
	case ScopeConnector:
		return 2
	case ScopeServer:
		return 1
	default:
		return 0
	}
}

// normalise fills the defaults and refuses a rule that cannot mean
// anything. The database checks the same things; this is what turns a
// violation into a sentence an administrator can act on.
func (p *ApprovalPolicy) normalise() error {
	p.Name = strings.TrimSpace(p.Name)
	p.ScopeID = strings.TrimSpace(p.ScopeID)
	p.ToolName = strings.TrimSpace(p.ToolName)
	if p.Name == "" {
		return fmt.Errorf("%w: it needs a name", ErrInvalidPolicy)
	}
	if p.Scope == "" {
		p.Scope = ScopeOrganization
	}
	if p.Effect == "" {
		p.Effect = EffectRequire
	}
	if p.TTL == 0 {
		p.TTL = int(defaultTTL.Seconds())
	}
	switch p.Scope {
	case ScopeOrganization:
		p.ScopeID = ""
	case ScopeServer, ScopeConnector, ScopeTool:
		if p.ScopeID == "" {
			return fmt.Errorf("%w: a policy scoped to a %s has to say which one", ErrInvalidPolicy, p.Scope)
		}
	default:
		return fmt.Errorf("%w: unknown scope %q", ErrInvalidPolicy, p.Scope)
	}
	switch p.Trigger {
	case TriggerDestructive:
		p.ToolName, p.Conditions = "", nil
	case TriggerTool:
		if p.ToolName == "" {
			return fmt.Errorf("%w: a policy that names a tool needs the tool's name", ErrInvalidPolicy)
		}
		p.Conditions = nil
	case TriggerCondition:
		if len(p.Conditions) == 0 {
			return fmt.Errorf("%w: a policy that matches arguments needs at least one condition", ErrInvalidPolicy)
		}
		for i, c := range p.Conditions {
			if strings.TrimSpace(c.Arg) == "" {
				return fmt.Errorf("%w: condition %d needs the argument it is about", ErrInvalidPolicy, i+1)
			}
			if !validOp(c.Op) {
				return fmt.Errorf("%w: unknown condition operator %q", ErrInvalidPolicy, c.Op)
			}
		}
	default:
		return fmt.Errorf("%w: unknown trigger %q", ErrInvalidPolicy, p.Trigger)
	}
	if p.Effect != EffectRequire && p.Effect != EffectAllow {
		return fmt.Errorf("%w: unknown effect %q", ErrInvalidPolicy, p.Effect)
	}
	if p.TTL < 60 || p.TTL > 604800 {
		return fmt.Errorf("%w: an approval has to last between a minute and a week", ErrInvalidPolicy)
	}
	return nil
}

func validOp(op string) bool {
	switch op {
	case OpEquals, OpNotEquals, OpGreaterThan, OpGreaterOrEqual, OpLessThan, OpLessOrEqual,
		OpContains, OpPrefix, OpIn, OpExists, OpAbsent:
		return true
	}
	return false
}

// matches evaluates one condition against the call's arguments. An
// argument that is not there fails every comparison except absent, so a
// model cannot get past a rule about an amount by leaving the amount out.
func (c ApprovalCondition) matches(args map[string]any) bool {
	v, ok := lookup(args, c.Arg)
	switch c.Op {
	case OpExists:
		return ok
	case OpAbsent:
		return !ok
	}
	if !ok {
		return false
	}
	switch c.Op {
	case OpEquals:
		return sameValue(v, c.Value)
	case OpNotEquals:
		return !sameValue(v, c.Value)
	case OpGreaterThan, OpGreaterOrEqual, OpLessThan, OpLessOrEqual:
		return compare(v, c.Value, c.Op)
	case OpContains:
		return contains(v, c.Value)
	case OpPrefix:
		s, ok := v.(string)
		want, wok := c.Value.(string)
		return ok && wok && strings.HasPrefix(s, want)
	case OpIn:
		list, ok := c.Value.([]any)
		if !ok {
			return false
		}
		for _, want := range list {
			if sameValue(v, want) {
				return true
			}
		}
	}
	return false
}

// lookup walks a dotted path into the arguments.
func lookup(args map[string]any, path string) (any, bool) {
	var cur any = args
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// sameValue compares two decoded JSON values. Numbers are compared as
// numbers, because 1 from a policy and 1.0 from a model are the same
// amount; everything else is compared by its encoding, which handles
// objects and arrays without a reflection walk.
func sameValue(a, b any) bool {
	if x, ok := toFloat(a); ok {
		if y, ok := toFloat(b); ok {
			return x == y
		}
		return false
	}
	ea, err := json.Marshal(a)
	if err != nil {
		return false
	}
	eb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(ea) == string(eb)
}

func compare(a, b any, op string) bool {
	x, ok := toFloat(a)
	y, yok := toFloat(b)
	if !ok || !yok {
		// Strings order too, which is what makes a condition on a date or
		// an identifier work without teaching this package about either.
		sa, aok := a.(string)
		sb, bok := b.(string)
		if !aok || !bok {
			return false
		}
		return orders(strings.Compare(sa, sb), op)
	}
	switch {
	case x < y:
		return orders(-1, op)
	case x > y:
		return orders(1, op)
	default:
		return orders(0, op)
	}
}

func orders(sign int, op string) bool {
	switch op {
	case OpGreaterThan:
		return sign > 0
	case OpGreaterOrEqual:
		return sign >= 0
	case OpLessThan:
		return sign < 0
	case OpLessOrEqual:
		return sign <= 0
	}
	return false
}

func contains(v, want any) bool {
	switch x := v.(type) {
	case string:
		s, ok := want.(string)
		return ok && strings.Contains(x, s)
	case []any:
		for _, item := range x {
			if sameValue(item, want) {
				return true
			}
		}
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

// splitApprovalID takes the approval argument out of the call. It is not
// a tool parameter and must never reach an upstream, so it is removed
// whether or not it names anything.
func splitApprovalID(args map[string]any) (string, map[string]any) {
	if len(args) == 0 {
		return "", map[string]any{}
	}
	id, _ := args[ArgApprovalID].(string)
	out := make(map[string]any, len(args))
	for k, v := range args {
		if k == ArgApprovalID {
			continue
		}
		out[k] = v
	}
	return strings.TrimSpace(id), out
}

// canonical encodes the arguments for sealing and for comparison.
// encoding/json writes a map's keys in order, so the same call always
// produces the same bytes.
func canonical(args map[string]any) ([]byte, error) {
	if args == nil {
		args = map[string]any{}
	}
	b, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("encode call arguments: %w", err)
	}
	return b, nil
}

func conditionsFor(p ApprovalPolicy, encoded []byte) any {
	if p.Trigger != TriggerCondition {
		return nil
	}
	return encoded
}

func orDefault(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// scanRequest reads the common columns, and the sealed arguments only
// where a caller asked for them: they are the one column that is worth
// keeping shut.
func scanRequest(row pgx.Row, sealed *[]byte) (*ApprovalRequest, error) {
	var r ApprovalRequest
	var state string
	dest := []any{&r.ID, &r.OrgID, &r.PolicyID, &r.PolicyName, &r.ServerID, &r.ConnectorID, &r.ToolID, &r.ToolName,
		&r.RequestedBy, &r.RequesterKind, &r.RequesterDisplay, &state, &r.CreatedAt, &r.ExpiresAt, &r.TTL,
		&r.DecidedBy, &r.DecidedAt, &r.CancelledAt, &r.ConsumedAt, &r.Reason, &r.AcknowledgedAt, &r.Acknowledgement}
	if sealed != nil {
		dest = append(dest, sealed)
	}
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	r.State = State(state)
	return &r, nil
}

func scanPolicies(ctx context.Context, tx pgx.Tx, query string, args ...any) ([]ApprovalPolicy, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ApprovalPolicy
	for rows.Next() {
		var p ApprovalPolicy
		var scope, trigger, effect string
		var conditions []byte
		if err := rows.Scan(&p.ID, &p.Name, &scope, &p.ScopeID, &trigger, &p.ToolName, &conditions, &effect,
			&p.TTL, &p.Enabled, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.Scope, p.Trigger, p.Effect = Scope(scope), Trigger(trigger), Effect(effect)
		if len(conditions) > 0 {
			if err := json.Unmarshal(conditions, &p.Conditions); err != nil {
				return nil, fmt.Errorf("decode conditions of policy %s: %w", p.ID, err)
			}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
