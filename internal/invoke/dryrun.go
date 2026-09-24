package invoke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

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
	// The engine redacts headers whose names look like credentials, but a
	// credential placeholder can sit anywhere: a query parameter, a body
	// field, another header. Every rendered value that equals a decrypted
	// credential is replaced, whatever it is called.
	scrubEnv(preview, resolved.Env, vars.Auth)
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
	meta := map[string]any{"connector": c.Connector.ID, "server": c.ServerID}
	if c.Draft {
		meta["draft"] = true
	}
	e.Audit.Emit(ctx, audit.Event{
		OrgID: c.Connector.OrgID, Category: audit.CategoryTool, Action: "tool.dry_run", Outcome: audit.Success,
		ActorKind: kind, ActorID: id,
		TargetKind: "tool", TargetID: c.Tool.ID, TargetDisplay: c.Tool.Name,
		Meta: meta,
	})
}

// minSecretLen is the shortest credential value that is scrubbed. Shorter
// values ("1", "true", "eu") would redact ordinary text and say nothing
// useful about the credential anyway.
const minSecretLen = 4

// secret is one credential value and the placeholder that names it.
type secret struct {
	label string // e.g. env.API_KEY
	value string
}

// secretsOf lists the values of one placeholder namespace that are long
// enough to scrub. Names are sorted so that two credentials sharing a
// value always redact to the same label.
func secretsOf(namespace string, values map[string]string) []secret {
	names := make([]string, 0, len(values))
	for k, v := range values {
		if len(v) >= minSecretLen {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	out := make([]secret, 0, len(names))
	for _, k := range names {
		out = append(out, secret{label: namespace + "." + k, value: values[k]})
	}
	return out
}

// scrubEnv replaces every credential value in a preview with a label
// naming it: <redacted:env.NAME> for connector credentials, and
// <redacted:auth.NAME> for what upstream auth prepared (a stored token, a
// basic-auth pair). It covers the URL, header values, body, SQL and string
// arguments, and each value as written, query-escaped, path-escaped and
// JSON-escaped, which are the forms a template renders it in.
func scrubEnv(p *engine.Preview, env, auth map[string]string) {
	if p == nil {
		return
	}
	r := newSecretReplacer(secretsOf("env", env), secretsOf("auth", auth))
	if r == nil {
		return
	}
	p.URL = r.Replace(p.URL)
	p.Body = r.Replace(p.Body)
	p.SQL = r.Replace(p.SQL)
	for k, v := range p.Headers {
		p.Headers[k] = r.Replace(v)
	}
	for i, a := range p.Args {
		if s, ok := a.(string); ok {
			p.Args[i] = r.Replace(s)
		}
	}
}

// newSecretReplacer builds one replacer over every form of every secret,
// longest needle first. strings.Replacer tries its pairs in argument order
// at each position and never rescans its own output, so a secret that
// contains another is redacted whole and a replacement is never redacted
// again. It is nil when there is nothing to scrub.
func newSecretReplacer(sets ...[]secret) *strings.Replacer {
	type pair struct{ needle, label string }
	seen := map[string]bool{}
	var pairs []pair
	for _, set := range sets {
		for _, s := range set {
			for _, form := range encodedForms(s.value) {
				if len(form) < minSecretLen || seen[form] {
					continue
				}
				seen[form] = true
				pairs = append(pairs, pair{needle: form, label: "<redacted:" + s.label + ">"})
			}
		}
	}
	if len(pairs) == 0 {
		return nil
	}
	sort.SliceStable(pairs, func(i, j int) bool { return len(pairs[i].needle) > len(pairs[j].needle) })
	args := make([]string, 0, 2*len(pairs))
	for _, p := range pairs {
		args = append(args, p.needle, p.label)
	}
	return strings.NewReplacer(args...)
}

// encodedForms is a value as written and as each renderer escapes it.
func encodedForms(v string) []string {
	forms := []string{v, url.QueryEscape(v), url.PathEscape(v)}
	// JSON, both with and without HTML escaping (<, >, & as \u003c...).
	for _, html := range []bool{true, false} {
		var b strings.Builder
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(html)
		if err := enc.Encode(v); err != nil {
			continue
		}
		s := strings.TrimSuffix(b.String(), "\n")
		forms = append(forms, strings.TrimSuffix(strings.TrimPrefix(s, `"`), `"`))
	}
	return forms
}
