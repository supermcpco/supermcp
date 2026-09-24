// Package invoke runs one tool call end to end: resolve the connector,
// prepare upstream auth, execute through the engine, shape the response,
// convert it to MCP content and record the invocation.
package invoke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/dbpool"
	"github.com/supermcpco/supermcp/internal/dlp"
	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/engine/database"
	"github.com/supermcpco/supermcp/internal/engine/graphql"
	"github.com/supermcpco/supermcp/internal/engine/rest"
	"github.com/supermcpco/supermcp/internal/governance"
	"github.com/supermcpco/supermcp/internal/httpclient"
	"github.com/supermcpco/supermcp/internal/ssrf"
	"github.com/supermcpco/supermcp/internal/telemetry"
	"github.com/supermcpco/supermcp/internal/tenant"
	"github.com/supermcpco/supermcp/internal/tool"
	"github.com/supermcpco/supermcp/internal/transform"
	"github.com/supermcpco/supermcp/internal/upstreamauth"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

// Deps are the executor's collaborators.
type Deps struct {
	DB         *tenant.DB
	Connectors *connector.Service
	Clients    *httpclient.Factory
	Pools      *dbpool.Registry
	SQLiteRoot string
	Log        *slog.Logger
	NewID      func() string
	// Audit and Policies record the call in the tamper-evident stream. A
	// nil Audit discards, which is what a test or a cut-down build gets.
	Audit    audit.Sink
	Policies *audit.Policies
	// Metrics observes every finished call. A nil Metrics records nothing.
	Metrics *telemetry.Metrics
	// Tracer records where the time inside a call went. A nil Tracer
	// records nothing and costs nothing.
	Tracer *telemetry.Tracer
	// MaxBlobBytes is the embed-or-link threshold for binary content.
	MaxBlobBytes int64
	// Approvals puts a person between the authorisation decision and the
	// engine, for the calls an organisation has said need one. Nil means
	// no call ever waits.
	Approvals Approver
	// DLP screens arguments on the way out and results on the way back.
	// Nil screens nothing, which is what an instance with no policies and
	// every test gets.
	DLP *dlp.Policies
	// Cache remembers read-only results for as long as the adapter said
	// they stay true. Nil caches nothing.
	Cache *Cache
	// Content converts binary bodies to MCP content. Nil embeds up to
	// MaxBlobBytes and refuses anything larger.
	Content *Content
}

// Approver decides whether a call may run now. *governance.Approvals
// satisfies it; the interface is here so a cut-down build can leave it out.
type Approver interface {
	Check(ctx context.Context, c governance.CallRef) (*governance.Outcome, error)
}

// Executor runs tool calls.
type Executor struct {
	Deps
	engines map[adapter.TransportType]engine.Engine
}

// New builds an executor.
func New(d Deps) *Executor {
	if d.MaxBlobBytes <= 0 {
		d.MaxBlobBytes = 8 << 20
	}
	return &Executor{Deps: d, engines: map[adapter.TransportType]engine.Engine{
		adapter.TransportHTTP:     rest.Engine{},
		adapter.TransportGraphQL:  graphql.Engine{},
		adapter.TransportDatabase: &database.Engine{Pools: d.Pools, SQLiteRoot: d.SQLiteRoot},
	}}
}

// Call is one invocation.
type Call struct {
	Principal *authz.Principal
	ServerID  string
	Tool      *connector.Tool
	Connector *connector.Connector
	Args      map[string]any
	// Draft marks a dry run of an unsaved definition; the audit event
	// says so, since Tool is not (or not yet) what is stored.
	Draft bool
}

// Result is the MCP-shaped outcome.
type Result struct {
	Content    []mcp.Content
	Structured any
	IsError    bool
	Meta       engine.Meta
	// UpstreamStatus is the status of an upstream refusal the caller is
	// shown as content rather than as an error. It is kept so the metric
	// can tell the upstream's fault from the caller's; zero otherwise.
	UpstreamStatus int
}

// Execute runs the call and records it.
func (e *Executor) Execute(ctx context.Context, c Call) (*Result, error) {
	start := time.Now()
	// The identifier is minted here rather than at the insert, so that a
	// data-loss finding can name the call it came from before the call has
	// finished.
	id := e.NewID()
	ctx, span := e.Tracer.Start(ctx, "tool.call",
		telemetry.Str("tool", c.Tool.Name),
		telemetry.Str("connector", c.Connector.ID),
		telemetry.Str("transport", string(c.Connector.Transport.Type)))
	defer span.End()
	res, err := e.awaitApproval(ctx, &c)
	if res == nil && err == nil {
		res, err = e.run(ctx, c, id)
	}
	dur := time.Since(start)
	e.record(ctx, c, id, res, err, dur)
	if err != nil {
		return &Result{Content: []mcp.Content{&mcp.TextContent{Text: userFacing(err)}}, IsError: true}, nil
	}
	return res, nil
}

func (e *Executor) run(ctx context.Context, c Call, invocationID string) (*Result, error) {
	eng, ok := e.engines[c.Connector.Transport.Type]
	if !ok {
		return nil, fmt.Errorf("transport %s: %w", c.Connector.Transport.Type, engine.ErrUnsupported)
	}
	// A hit skips the connector read and the credential decrypt, but stays
	// inside run so the call is still recorded and audited: a cached call
	// is still a call.
	if hit, ok := e.Cache.Lookup(ctx, c); ok {
		return hit, nil
	}
	resolved, err := e.Connectors.Resolve(ctx, c.Connector.OrgID, c.Connector.ID)
	if err != nil {
		return nil, err
	}
	def := c.Tool.Definition
	args := applyDefaults(def, c.Args)
	// The last point at which what the caller sent is still ours. A
	// masking policy replaces the values here and not in c.Args, so the
	// record still shows what was actually asked for.
	screened, err := e.screen(ctx, c, invocationID, dlp.StageArguments, args)
	if err != nil {
		return nil, err
	}
	if m, ok := screened.(map[string]any); ok {
		args = m
	}
	vars := tmpl.Vars{Params: args, Env: resolved.Env, Caller: callerVars(c)}

	// Per-connector HTTP client; the token endpoints share it.
	var client *httpclient.Client
	if c.Connector.Transport.Type != adapter.TransportDatabase {
		policy := httpclient.DefaultPolicy()
		if c.Connector.Transport.Timeout != 0 {
			policy.TotalTimeout = time.Duration(c.Connector.Transport.Timeout)
		}
		if def.Timeout != 0 && time.Duration(def.Timeout) < policy.TotalTimeout {
			policy.TotalTimeout = time.Duration(def.Timeout)
		}
		client = e.Clients.For(c.Connector.ID, c.Connector.Version, policy)
	}
	var doer engine.HTTPDoer
	if client != nil {
		doer = client
	}
	auth, vars, err := upstreamauth.Prepare(ctx, resolved.Connector, vars, upstreamauth.Deps{
		HTTP:  doer,
		Store: &connector.TokenStore{S: e.Connectors, OrgID: c.Connector.OrgID},
		RefreshedRefreshToken: func(ctx context.Context, id, rt string) error {
			return e.Connectors.RotateRefreshToken(ctx, c.Connector.OrgID, id, rt)
		},
	})
	if err != nil {
		return nil, err
	}
	req := &engine.Request{Connector: resolved.Connector, Tool: def, Vars: vars, Auth: auth, HTTP: doer,
		Limits: engine.Limits{MaxRows: def.Operation.MaxRows, MaxInlineBytes: 16 << 20}}
	upstreamCtx, upstreamSpan := e.Tracer.Start(ctx, "upstream."+string(c.Connector.Transport.Type))
	resp, err := eng.Execute(upstreamCtx, req)
	upstreamSpan.End()
	var ue *engine.UpstreamError
	if err != nil && !errors.As(err, &ue) {
		return nil, err
	}
	out := &Result{Meta: resp.Meta}
	if resp.Stream != nil {
		content, cerr := e.Content.Binary(ctx, c, resp, e.MaxBlobBytes)
		if cerr != nil {
			return nil, cerr
		}
		out.Content = content
		return out, nil
	}
	body := resp.Body
	if def.Response != nil && def.Response.Transform != nil && ue == nil {
		o := transform.Apply(&transform.Spec{JMESPath: def.Response.Transform.JMESPath, MaxBytes: def.Response.MaxBytes, FallbackToRaw: def.Response.FallbackToRaw}, body)
		if o.Fatal {
			return nil, fmt.Errorf("%w: %w", transform.ErrFatal, o.Err)
		}
		if o.Err != nil && e.Log != nil {
			e.Log.Warn("response transform failed, returning raw", "tool", def.Name, "err", o.Err)
		}
		body = o.Value
	}
	if len(resp.Headers) > 0 {
		if m, ok := body.(map[string]any); ok {
			m["_headers"] = resp.Headers
		}
	}
	// The result is screened after the transform, so a policy sees what
	// the caller would have seen. A refusal here cannot undo the upstream
	// call, which has already happened, so it is reported as a failed call
	// rather than as an error that hides what took place.
	if screenedBody, serr := e.screen(ctx, c, invocationID, dlp.StageResult, body); serr != nil {
		if errors.Is(serr, dlp.ErrRefused) {
			out.IsError = true
			out.Content = []mcp.Content{&mcp.TextContent{Text: userFacing(serr)}}
			return out, nil
		}
		return nil, serr
	} else if screenedBody != nil {
		body = screenedBody
	}
	text := renderText(body)
	if ue != nil {
		out.IsError = true
		out.UpstreamStatus = ue.Status
		hint := ue.Hint
		if hint == "" {
			hint = text
		}
		out.Content = []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Upstream returned HTTP %d.\n%s", ue.Status, truncate(hint, 4000))}}
		return out, nil
	}
	out.Content = []mcp.Content{&mcp.TextContent{Text: text}}
	if def.Output != nil && def.Output.N != nil {
		out.Structured = body
	}
	e.Cache.Store(ctx, c, out)
	return out, nil
}

// awaitApproval asks whether a person has to agree to this call first.
// Nothing blocks: a tool call cannot be held open while somebody is found,
// so a call that needs approval comes straight back naming the request it
// raised. c is a pointer because a replay returns the arguments that were
// approved, and those are what runs, what is recorded and what is audited.
func (e *Executor) awaitApproval(ctx context.Context, c *Call) (*Result, error) {
	if e.Approvals == nil {
		return nil, nil
	}
	ann := tool.Derive(c.Tool.Definition, c.Connector.Transport.Type, c.Connector.ReadOnly)
	kind, id, display := "anonymous", "", ""
	if c.Principal != nil {
		kind, id, display = string(c.Principal.Kind), c.Principal.ID, c.Principal.Email
	}
	out, err := e.Approvals.Check(ctx, governance.CallRef{
		OrgID: c.Connector.OrgID, ServerID: c.ServerID, ConnectorID: c.Connector.ID,
		ToolID: c.Tool.ID, ToolName: c.Tool.Name, Destructive: ann.DestructiveHint,
		ActorKind: kind, ActorID: id, ActorDisplay: display, Args: c.Args,
	})
	if err != nil {
		return nil, err
	}
	c.Args = out.Args
	if !out.Required {
		return nil, nil
	}
	return &Result{Content: []mcp.Content{&mcp.TextContent{Text: out.Message}},
		Structured: out.Notice(), IsError: true}, nil
}

// screen runs the organisation's data-loss policy over one half of a call
// and records what it found. A policy that cannot be read does not stop
// the call: refusing every tool call because a settings table is
// unreachable is a worse failure than the one it guards against, and the
// warning says so where an operator will see it.
func (e *Executor) screen(ctx context.Context, c Call, invocationID string, stage dlp.Stage, v any) (any, error) {
	scr, err := e.DLP.Screen(ctx, c.Connector.OrgID, c.Connector.ID, c.Tool.ID, stage, v)
	switch {
	case errors.Is(err, dlp.ErrRefused):
		e.recordFindings(ctx, c, invocationID, stage, scr)
		return nil, err
	case err != nil:
		if e.Log != nil {
			e.Log.Warn("data-loss policy unreadable, this half of the call was not screened",
				"err", err, "tool", c.Tool.Name, "stage", stage)
		}
		return v, nil
	case !scr.Applied:
		return v, nil
	}
	e.recordFindings(ctx, c, invocationID, stage, scr)
	return scr.Value, nil
}

func (e *Executor) recordFindings(ctx context.Context, c Call, invocationID string, stage dlp.Stage, scr dlp.Screened) {
	if len(scr.Result.Findings) == 0 {
		return
	}
	err := e.DLP.Record(ctx, c.Connector.OrgID, dlp.Recording{
		InvocationID: invocationID, PolicyID: scr.ScanPolicy.ID, ConnectorID: c.Connector.ID,
		ToolID: c.Tool.ID, ToolName: c.Tool.Name, Stage: stage, Action: scr.ScanPolicy.Action,
		Result: scr.Result,
	})
	if err != nil && e.Log != nil {
		e.Log.Error("record data-loss findings", "err", err, "tool", c.Tool.Name)
	}
}

// applyDefaults fills schema defaults for absent params.
func applyDefaults(def *adapter.Tool, args map[string]any) map[string]any {
	out := make(map[string]any, len(args))
	for k, v := range args {
		out[k] = v
	}
	if def.Input == nil || def.Input.N == nil {
		return out
	}
	props := adapter.MapGet(def.Input.N, "properties")
	for _, name := range adapter.MapKeys(props) {
		if _, ok := out[name]; ok {
			continue
		}
		if d := adapter.MapGet(adapter.MapGet(props, name), "default"); d != nil {
			if v, err := adapter.NodeValue(d); err == nil {
				out[name] = v
			}
		}
	}
	return out
}

func callerVars(c Call) map[string]string {
	m := map[string]string{"server": c.ServerID}
	if c.Principal != nil {
		m["sub"] = c.Principal.ID
		m["email"] = c.Principal.Email
		m["org"] = c.Principal.OrgID
		m["authMethod"] = c.Principal.AuthMethod
	}
	return m
}

func renderText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

func userFacing(err error) string {
	switch {
	case errors.Is(err, engine.ErrUnsupported):
		return "This tool's transport or auth type is not supported yet: " + err.Error()
	case errors.Is(err, tmpl.ErrUnset):
		return "A required value is missing: " + err.Error()
	case errors.Is(err, dlp.ErrRefused):
		return "This workspace's data-loss policy refused the call: " + err.Error()
	}
	return "Tool call failed: " + truncate(err.Error(), 2000)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// record writes the invocation row and the audit event. The row is what
// the tool-call screen reads; the event is what an auditor reads, and only
// the latter is bound into the hash chain.
func (e *Executor) record(ctx context.Context, c Call, id string, res *Result, callErr error, dur time.Duration) {
	status := "success"
	var errText *string
	if callErr != nil {
		status = "error"
		s := truncate(callErr.Error(), 4000)
		errText = &s
		if errors.Is(callErr, context.DeadlineExceeded) {
			status = "timeout"
		}
	} else if res != nil && res.IsError {
		status = "error"
	}
	// The tool-call screen reads this row, and the organisation's payload
	// policy governs what may be kept of a call. It was written to the
	// audit event alone before, which left the arguments of every call in
	// this table in full whatever the policy said.
	var outText any
	if res != nil && len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			outText = truncate(tc.Text, 64<<10)
		}
	}
	inValue, outValue := audit.Apply(e.Policies.Mode(ctx, c.Connector.OrgID), c.Args, outText)
	var input, output []byte
	if inValue != nil {
		input, _ = json.Marshal(inValue)
	}
	if outValue != nil {
		output, _ = json.Marshal(outValue)
	}
	var upstream *int
	if res != nil && res.Meta.UpstreamDurationMS > 0 {
		u := int(res.Meta.UpstreamDurationMS)
		upstream = &u
	}
	principalKind, principalID, authMethod := "anonymous", "", "none"
	if c.Principal != nil {
		principalKind, principalID, authMethod = string(c.Principal.Kind), c.Principal.ID, c.Principal.AuthMethod
	}
	err := e.DB.Tx(tenant.WithOrg(ctx, c.Connector.OrgID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO tool_invocations (id, organization_id, server_id, connector_id, tool_id, tool_name, principal_kind, principal_id, auth_method, status, duration_ms, upstream_ms, input, output, error)
			VALUES ($1,$2,NULLIF($3,''),$4,$5,$6,$7,NULLIF($8,''),$9,$10,$11,$12,$13,$14,$15)`,
			id, c.Connector.OrgID, c.ServerID, c.Connector.ID, c.Tool.ID, c.Tool.Name, principalKind, principalID, authMethod, status, dur.Milliseconds(), upstream, input, output, errText)
		return err
	})
	if err != nil && e.Log != nil {
		e.Log.Error("record invocation", "err", err, "tool", c.Tool.Name)
	}
	e.auditCall(ctx, c, status, errText, dur, principalKind, principalID, authMethod, res)

	connectorType := string(c.Connector.Transport.Type)
	e.Metrics.ObserveToolCall(connectorType, c.Tool.Name, telemetry.CallStatus(status), errorClass(callErr, res), dur)
	if res != nil {
		e.Metrics.ObserveUpstream(connectorType, time.Duration(res.Meta.UpstreamDurationMS)*time.Millisecond)
	}
}

// errorClass sorts a failure into the closed set the metric labels carry.
// The set is closed on purpose: a class taken from an upstream message
// would put an unbounded number of series behind one metric name.
func errorClass(err error, res *Result) telemetry.ErrorClass {
	var ue *engine.UpstreamError
	switch {
	case err == nil && res != nil && res.IsError:
		return classOfStatus(res.UpstreamStatus)
	case err == nil:
		return telemetry.ClassNone
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return telemetry.ClassTimeout
	case errors.As(err, &ue):
		return classOfStatus(ue.Status)
	// An open breaker means the upstream has been failing long enough to
	// stop asking, so it belongs with the upstream's own failures.
	case errors.Is(err, httpclient.ErrBreakerOpen):
		return telemetry.ClassUpstream5xx
	case errors.Is(err, dlp.ErrRefused):
		return telemetry.ClassPolicy
	case errors.Is(err, transform.ErrFatal):
		return telemetry.ClassTransform
	case errors.Is(err, engine.ErrUnsupported):
		return telemetry.ClassUnsupported
	// Something the connector was set up with is missing or points
	// somewhere it may not: an operator fixes these, not an engineer.
	case errors.Is(err, tmpl.ErrUnset), errors.Is(err, ssrf.ErrBlocked),
		errors.Is(err, connector.ErrMissingCredential), errors.Is(err, connector.ErrNotFound):
		return telemetry.ClassConfig
	}
	return telemetry.ClassInternal
}

func classOfStatus(status int) telemetry.ErrorClass {
	switch {
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return telemetry.ClassAuth
	case status >= 500:
		return telemetry.ClassUpstream5xx
	case status >= 400:
		return telemetry.ClassUpstream4xx
	}
	return telemetry.ClassOther
}

// auditCall records the call in the audit stream, with as much of the
// payload as the organisation's policy allows.
func (e *Executor) auditCall(ctx context.Context, c Call, status string, errText *string, dur time.Duration,
	principalKind, principalID, authMethod string, res *Result,
) {
	if e.Audit == nil {
		return
	}
	outcome := audit.Success
	if status != "success" {
		outcome = audit.Failure
	}
	var output any
	if res != nil && len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			output = truncate(tc.Text, 64<<10)
		}
	}
	in, out := audit.Apply(e.Policies.Mode(ctx, c.Connector.OrgID), c.Args, output)
	meta := map[string]any{
		"durationMs": dur.Milliseconds(),
		"connector":  c.Connector.ID,
		"authMethod": authMethod,
	}
	if c.ServerID != "" {
		meta["server"] = c.ServerID
	}
	if errText != nil {
		meta["error"] = *errText
	}
	var payload any
	if in != nil || out != nil {
		payload = map[string]any{"input": in, "output": out}
	}
	e.Audit.Emit(ctx, audit.Event{
		OrgID: c.Connector.OrgID, Category: audit.CategoryTool, Action: "tool.invoke", Outcome: outcome,
		ActorKind: principalKind, ActorID: principalID,
		TargetKind: "tool", TargetID: c.Tool.ID, TargetDisplay: c.Tool.Name,
		Payload: payload, Meta: meta,
	})
}
