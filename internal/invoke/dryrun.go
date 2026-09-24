package invoke

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/upstreamauth"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

// A dry run answers the question a person asks before they trust a tool
// with real arguments: what exactly would leave this instance? It renders
// the request the engine would send — the URL, the headers, the body, or
// the statement and its bound arguments — and sends nothing.
//
// Nothing reaches the network, which is the one property that makes it
// safe to offer to anybody who may call the tool. That includes the
// credential: an upstream that mints a token from a token endpoint would
// need a request of its own, so a dry run does not fetch one and says
// that the credential is missing rather than quietly rendering without it.

// DryRunArg is the argument that turns a tool call into a preview. It
// shares the underscore convention with the approval identifier, so a
// model that has seen one can guess the other.
const DryRunArg = "_dry_run"

// errNoNetworkInDryRun is what the refusing transport returns. It reaches
// the caller as the note on the preview, not as a failure.
var errNoNetworkInDryRun = errors.New("a dry run sends nothing, so no credential could be fetched")

// refusingDoer stands in for the HTTP client while a request is being
// rendered. Anything that tries to use it is trying to reach the network.
type refusingDoer struct{}

func (refusingDoer) Do(*http.Request) (*http.Response, error) { return nil, errNoNetworkInDryRun }

// DryRun renders what a call would send. The caller has already been
// authorised to invoke the tool: a preview shows the shape of the
// credential's use and the arguments, which is not something to hand to
// somebody who may not make the call itself.
func (e *Executor) DryRun(ctx context.Context, c Call) (*engine.Preview, error) {
	eng, ok := e.engines[c.Connector.Transport.Type]
	if !ok {
		return nil, fmt.Errorf("transport %s: %w", c.Connector.Transport.Type, engine.ErrUnsupported)
	}
	resolved, err := e.Connectors.Resolve(ctx, c.Connector.OrgID, c.Connector.ID)
	if err != nil {
		return nil, err
	}
	def := c.Tool.Definition
	args := applyDefaults(def, stripControlArgs(c.Args))
	vars := tmpl.Vars{Params: args, Env: resolved.Env, Caller: callerVars(c)}

	// Auth is prepared against a transport that refuses, so a scheme that
	// only needs what is already stored (a key, a header, a signature)
	// renders as it would on the wire, and one that would have to ask an
	// upstream for a token renders without it and says so.
	note := ""
	auth, authVars, err := upstreamauth.Prepare(ctx, resolved.Connector, vars, upstreamauth.Deps{
		HTTP:  refusingDoer{},
		Store: &connector.TokenStore{S: e.Connectors, OrgID: c.Connector.OrgID},
	})
	switch {
	case err == nil:
		vars = authVars
	case errors.Is(err, errNoNetworkInDryRun):
		auth, note = nil, "The credential is not shown: this tool's upstream issues one per call, and a dry run sends nothing."
	default:
		return nil, err
	}

	req := &engine.Request{Connector: resolved.Connector, Tool: def, Vars: vars, Auth: auth,
		HTTP:   refusingDoer{},
		Limits: engine.Limits{MaxRows: def.Operation.MaxRows, MaxInlineBytes: 16 << 20}}
	preview, err := eng.DryRun(ctx, req)
	if err != nil {
		return nil, err
	}
	preview.Note = note
	e.auditDryRun(ctx, c)
	return preview, nil
}

// stripControlArgs removes the arguments that steer this system rather
// than the tool: a preview of the request must not show them as though the
// upstream had been asked for them.
func stripControlArgs(args map[string]any) map[string]any {
	out := make(map[string]any, len(args))
	for k, v := range args {
		if k == DryRunArg || k == "_approval" {
			continue
		}
		out[k] = v
	}
	return out
}

// WantsDryRun reports whether a call asked for a preview instead.
func WantsDryRun(args map[string]any) bool {
	v, ok := args[DryRunArg]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

// auditDryRun records the preview. Seeing the rendered request is close
// enough to making the call that an auditor reconstructing what somebody
// did needs it in the same stream.
func (e *Executor) auditDryRun(ctx context.Context, c Call) {
	if e.Audit == nil {
		return
	}
	kind, id := "anonymous", ""
	if c.Principal != nil {
		kind, id = string(c.Principal.Kind), c.Principal.ID
	}
	e.Audit.Emit(ctx, audit.Event{
		OrgID: c.Connector.OrgID, Category: audit.CategoryTool, Action: "tool.dry_run", Outcome: audit.Success,
		ActorKind: kind, ActorID: id,
		TargetKind: "tool", TargetID: c.Tool.ID, TargetDisplay: c.Tool.Name,
		Meta: map[string]any{"connector": c.Connector.ID, "server": c.ServerID},
	})
}
