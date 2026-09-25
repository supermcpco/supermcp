// Package mcp serves the Streamable HTTP endpoint clients connect to.
//
// The tool surface is computed per request, because it depends on who is
// calling: the server's connectors, filtered by the caller's permissions.
// tools/list is answered from that surface, and tools/call re-checks the
// name against it so a client cannot invoke something it was never shown.
package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/invoke"
	"github.com/supermcpco/supermcp/internal/mcpserver"
	"github.com/supermcpco/supermcp/internal/reqid"
	"github.com/supermcpco/supermcp/internal/telemetry"
	"github.com/supermcpco/supermcp/internal/tool"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// Deps are the endpoint's collaborators.
type Deps struct {
	Servers  *mcpserver.Service
	Authz    *authz.Evaluator
	Executor *invoke.Executor
	Log      *slog.Logger
	// Metrics observes surface builds and requests. A nil Metrics records
	// nothing.
	Metrics *telemetry.Metrics
	// Tracer records where the time inside a request went.
	Tracer  *telemetry.Tracer
	Version string
	// PublicURL is the externally visible base URL, used in the
	// WWW-Authenticate challenge.
	PublicURL string
	// JSONResponse serves application/json instead of SSE (some clients,
	// notably Copilot Studio, require it).
	JSONResponse bool
}

// Endpoint is the MCP HTTP handler.
type Endpoint struct {
	Deps
	handler *sdk.StreamableHTTPHandler

	// built holds the assembled MCP servers, keyed by the server, its
	// version and the caller. Assembling one means handing every tool's
	// JSON Schema to the SDK, which re-parses it: at 500 tools that is
	// about ten milliseconds and forty megabytes, paid on tools/list and
	// again on every tools/call. The same caller asking the same
	// unchanged server gets the same answer, so it is built once.
	mu    sync.Mutex
	built map[string]*builtServer
}

// builtServer is one assembled surface. sdk.Server is safe for concurrent
// sessions, which is what makes sharing it between requests possible.
type builtServer struct {
	srv     *sdk.Server
	names   map[string]bool
	expires time.Time
}

// builtTTL bounds how stale a shared surface may be. A tool added to a
// server, or a permission taken away, changes what tools/list shows within
// this window; a call is authorised against live state every time, so the
// window never widens what anyone may actually invoke.
const builtTTL = 30 * time.Second

// builtCap stops a busy instance with many servers and many callers from
// holding surfaces for ever. Expired entries go first, and only if that
// frees nothing does the cache start over.
const builtCap = 1024

type ctxKey int

const surfaceKey ctxKey = iota

// surface is the caller-visible tool set for one request.
type surface struct {
	server           *mcpserver.Server
	instructionsText string
	names            map[string]bool
	tools            []visibleTool
	// mcp is the assembled server, shared with every other request that
	// sees the same tools. nil until getServer assembles it.
	mcp    *sdk.Server
	err    error
	status int
	// method is the JSON-RPC method this request carried, recorded on the
	// way in so the HTTP layer can label the request with it once it knows
	// the status the client was given. One surface serves one request,
	// which is why the middleware writing it takes the surface and not the
	// shared server.
	method string
}

type visibleTool struct {
	tool      *connector.Tool
	connector *connector.Connector
	ann       tool.Annotations
}

// New builds the endpoint.
func New(d Deps) *Endpoint {
	e := &Endpoint{Deps: d}
	e.handler = sdk.NewStreamableHTTPHandler(e.getServer, &sdk.StreamableHTTPOptions{
		Stateless:                    true,
		JSONResponse:                 d.JSONResponse,
		Logger:                       d.Log,
		MaxRequestBodyBytes:          4 << 20,
		PropagateRequestCancellation: true,
	})
	return e
}

// Routes mounts the endpoint.
func (e *Endpoint) Routes(r chi.Router) {
	r.Handle("/mcp/{server}", e.serve())
	r.Handle("/mcp/{server}/*", e.serve())
}

func (e *Endpoint) serve() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A stateless server has no stream to resume; answering 405 here
		// keeps clients that probe with GET from hanging.
		if r.Method == http.MethodGet {
			w.Header().Set("Allow", "POST, DELETE")
			writeRPCError(w, http.StatusMethodNotAllowed, -32000, "Method not allowed in stateless mode")
			e.Metrics.ObserveMCPRequest(routePattern(r), "", http.StatusMethodNotAllowed)
			return
		}
		ctx, span := e.Tracer.Start(r.Context(), "mcp.request", telemetry.Str("server", chi.URLParam(r, "server")))
		defer span.End()
		r = r.WithContext(ctx)

		start := time.Now()
		s := e.buildSurface(r)
		// Refusals are timed too. A slow refusal is still slow, and an
		// authorisation check that crawls hides completely in a latency
		// taken over successes alone.
		e.Metrics.ObserveSurfaceBuild(time.Since(start))
		if s.err != nil {
			if s.status == http.StatusUnauthorized {
				// Point the client at the metadata that tells it how to
				// obtain a token for this exact server (RFC 9728).
				resource := "/.well-known/oauth-protected-resource/mcp/" + chi.URLParam(r, "server")
				w.Header().Set("WWW-Authenticate", `Bearer realm="supermcp", resource_metadata="`+e.PublicURL+resource+`"`)
			}
			msg := s.err.Error()
			if s.status >= http.StatusInternalServerError {
				// A lookup that failed, not a refusal: its text can name
				// the database, so it goes to the log and the caller gets
				// the request id.
				id := middleware.GetReqID(ctx)
				log := e.Log
				if log == nil {
					log = slog.Default()
				}
				log.ErrorContext(ctx, "mcp request failed", "req_id", id, "path", r.URL.Path, "err", s.err)
				msg = reqid.Message(id)
			}
			writeRPCError(w, s.status, rpcCodeFor(s.status), msg)
			e.Metrics.ObserveMCPRequest(routePattern(r), s.method, s.status)
			return
		}
		// The pattern, never the server id: an endpoint label taken from
		// the URL would give every MCP server installed a series of its own.
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		e.handler.ServeHTTP(ww, r.WithContext(context.WithValue(ctx, surfaceKey, s)))
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}
		e.Metrics.ObserveMCPRequest(routePattern(r), s.method, status)
	}
}

// buildSurface resolves the server, checks membership and permissions, and
// collects the tools this caller may see. Every failure is a refusal, not
// an empty surface, so misconfiguration cannot silently widen access.
func (e *Endpoint) buildSurface(r *http.Request) *surface {
	ctx := r.Context()
	ref := chi.URLParam(r, "server")
	p, ok := authz.From(ctx)
	if !ok || p == nil || p.Kind == authz.KindAnonymous {
		return &surface{err: errors.New("authentication required"), status: http.StatusUnauthorized}
	}
	srv, err := e.Servers.GetByIDAnyOrg(ctx, ref)
	if errors.Is(err, mcpserver.ErrNotFound) {
		srv, err = e.Servers.GetBySlugAnyOrg(ctx, ref)
	}
	if errors.Is(err, mcpserver.ErrNotFound) {
		return &surface{err: errors.New("no such MCP server"), status: http.StatusNotFound}
	}
	if err != nil {
		return &surface{err: err, status: http.StatusInternalServerError}
	}
	if !srv.Enabled {
		return &surface{err: errors.New("this MCP server is disabled"), status: http.StatusForbidden}
	}
	// The caller must belong to the server's organisation, and a
	// server-bound credential must match this server.
	if p.OrgID != srv.OrgID {
		return &surface{err: errors.New("access denied"), status: http.StatusForbidden}
	}
	if p.ServerID != "" && p.ServerID != srv.ID {
		return &surface{err: errors.New("this credential is bound to a different server"), status: http.StatusForbidden}
	}
	// Everything above is per-request: who is calling, which server, and
	// whether they may reach it at all. What follows is the same for every
	// request that shares a key, so it is the part worth keeping.
	key := builtKey(srv, p)
	if b := e.cachedServer(key); b != nil {
		return &surface{server: srv, names: b.names, mcp: b.srv}
	}

	sf, err := e.Servers.Surface(ctx, srv)
	if err != nil {
		return &surface{err: err, status: http.StatusInternalServerError}
	}
	out := &surface{server: srv, names: map[string]bool{}}
	for _, st := range sf.Tools {
		ann := tool.Derive(st.Tool.Definition, st.Connector.Transport.Type, st.Connector.ReadOnly)
		d, err := e.Authz.Evaluate(ctx, p, authz.ToolsRead, authz.Resource{OrgID: srv.OrgID, ServerID: srv.ID, ConnectorID: st.Connector.ID, ToolID: st.Tool.ID})
		if err != nil {
			return &surface{err: err, status: http.StatusInternalServerError}
		}
		if !d.Allow || out.names[st.Tool.Name] {
			continue
		}
		out.names[st.Tool.Name] = true
		out.tools = append(out.tools, visibleTool{tool: st.Tool, connector: st.Connector, ann: ann})
	}
	out.instructionsText = sf.Instructions
	out.mcp = e.assemble(out)
	e.keepServer(key, &builtServer{srv: out.mcp, names: out.names, expires: time.Now().Add(builtTTL)})
	return out
}

// builtKey names a surface: the server as it stands, and everything about
// the caller that the permission check can read. Two callers who differ in
// any of it get their own.
func builtKey(srv *mcpserver.Server, p *authz.Principal) string {
	h := sha256.New()
	for _, part := range []string{
		srv.ID, strconv.FormatInt(srv.Version, 10),
		string(p.Kind), p.ID, p.OrgID, p.ServerID, p.AuthMethod,
		strings.Join(p.Scopes, " "), strconv.FormatBool(p.MFA),
	} {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (e *Endpoint) cachedServer(key string) *builtServer {
	e.mu.Lock()
	defer e.mu.Unlock()
	b := e.built[key]
	if b == nil || time.Now().After(b.expires) {
		return nil
	}
	return b
}

func (e *Endpoint) keepServer(key string, b *builtServer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.built == nil {
		e.built = map[string]*builtServer{}
	}
	if len(e.built) >= builtCap {
		now := time.Now()
		for k, old := range e.built {
			if now.After(old.expires) {
				delete(e.built, k)
			}
		}
		if len(e.built) >= builtCap {
			e.built = map[string]*builtServer{}
		}
	}
	e.built[key] = b
}

// assemble hands the visible tools to the SDK. It is the expensive half of
// a surface, and nothing in it depends on the request beyond what the key
// already covers.
func (e *Endpoint) assemble(s *surface) *sdk.Server {
	srv := sdk.NewServer(&sdk.Implementation{Name: s.server.Name, Version: e.Version},
		&sdk.ServerOptions{Instructions: s.instructionsText})
	for _, vt := range s.tools {
		srv.AddTool(mcpTool(vt), e.handlerFor(s.server, vt))
	}
	// recordMethod is outermost, so a call the guard refuses is still
	// labelled with the method it asked for. It reads the per-request
	// surface out of the context, because this server outlives the request.
	srv.AddReceivingMiddleware(recordMethod(), hiddenToolGuard(s.names))
	return srv
}

// getServer hands the SDK the server this request's surface names.
func (e *Endpoint) getServer(r *http.Request) *sdk.Server {
	s, _ := r.Context().Value(surfaceKey).(*surface)
	if s == nil || s.server == nil {
		return sdk.NewServer(&sdk.Implementation{Name: "supermcp", Version: e.Version}, nil)
	}
	if s.mcp == nil {
		// buildSurface always assembles; serving an empty tool set because
		// it somehow did not would look like a permission problem to the
		// client and like nothing at all here.
		s.mcp = e.assemble(s)
	}
	return s.mcp
}

// mcpTool converts a stored tool into the wire shape.
func mcpTool(vt visibleTool) *sdk.Tool {
	def := vt.tool.Definition
	t := &sdk.Tool{
		Name:        def.Name,
		Description: def.Description,
		InputSchema: inputSchema(def),
		Annotations: &sdk.ToolAnnotations{
			Title:           vt.ann.Title,
			ReadOnlyHint:    vt.ann.ReadOnlyHint,
			DestructiveHint: boolPtr(vt.ann.DestructiveHint),
			IdempotentHint:  vt.ann.IdempotentHint,
			OpenWorldHint:   boolPtr(vt.ann.OpenWorldHint),
		},
	}
	if def.Output != nil && def.Output.N != nil {
		if v, err := def.Output.Value(); err == nil {
			t.OutputSchema = v
		}
	}
	return t
}

func boolPtr(b bool) *bool { return &b }

// inputSchema returns the tool's JSON Schema with credential-named
// parameters removed: the operator supplies those, not the model.
func inputSchema(def *adapter.Tool) any {
	empty := map[string]any{"type": "object", "properties": map[string]any{}}
	if def.Input == nil || def.Input.N == nil {
		return empty
	}
	v, err := def.Input.Value()
	if err != nil {
		return empty
	}
	m, ok := v.(map[string]any)
	if !ok {
		return empty
	}
	if _, has := m["properties"]; !has {
		m["properties"] = map[string]any{}
	}
	m["type"] = "object"
	return m
}

// handlerFor runs one tool call after re-checking invoke permission.
func (e *Endpoint) handlerFor(server *mcpserver.Server, vt visibleTool) sdk.ToolHandler {
	return func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		// The caller comes from the request, not from the closure: this
		// handler is shared by every caller the surface key matches, and
		// the permission check below has to be about the one calling now.
		p, ok := authz.From(ctx)
		if !ok || p == nil {
			return nil, errors.New("authentication required")
		}
		res := authz.Resource{OrgID: server.OrgID, ServerID: server.ID, ConnectorID: vt.connector.ID, ToolID: vt.tool.ID, Destructive: vt.ann.DestructiveHint}
		d, err := e.Authz.Evaluate(ctx, p, authz.ToolsInvoke, res)
		if err != nil {
			return nil, err
		}
		if !d.Allow {
			return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{
				Text: "This tool is not available to you. It may belong to another workspace, or your role may not allow it.",
			}}}, nil
		}
		args := map[string]any{}
		if len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
				return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "Arguments must be a JSON object."}}}, nil
			}
		}
		// A client that asks for a preview gets the request this call
		// would have made and nothing leaves the instance. It is checked
		// after the permission test on purpose: seeing how a credential is
		// used is as privileged as using it.
		if invoke.WantsDryRun(args) {
			preview, err := e.Executor.DryRun(ctx, invoke.Call{
				Principal: p, ServerID: server.ID, Tool: vt.tool, Connector: vt.connector, Args: args,
			})
			if err != nil {
				return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{
					Text: "The request could not be rendered: " + err.Error()}}}, nil
			}
			return &sdk.CallToolResult{
				Content:           []sdk.Content{&sdk.TextContent{Text: renderPreview(preview)}},
				StructuredContent: preview,
			}, nil
		}
		out, err := e.Executor.Execute(ctx, invoke.Call{
			Principal: p, ServerID: server.ID, Tool: vt.tool, Connector: vt.connector, Args: args,
		})
		if err != nil {
			return nil, err
		}
		return &sdk.CallToolResult{Content: out.Content, StructuredContent: out.Structured, IsError: out.IsError}, nil
	}
}

// renderPreview writes a preview the way somebody reads a request, not
// the way JSON prints one.
func renderPreview(p *engine.Preview) string {
	var b strings.Builder
	if p.SQL != "" {
		b.WriteString("Nothing was sent. This call would run:\n\n")
		b.WriteString(p.SQL)
		for i, a := range p.Args {
			fmt.Fprintf(&b, "\n  $%d = %v", i+1, a)
		}
	} else {
		b.WriteString("Nothing was sent. This call would make the request:\n\n")
		fmt.Fprintf(&b, "%s %s\n", p.Method, p.URL)
		for _, k := range sortedHeaders(p.Headers) {
			fmt.Fprintf(&b, "%s: %s\n", k, p.Headers[k])
		}
		if p.Body != "" {
			b.WriteString("\n" + p.Body + "\n")
		}
	}
	if p.Note != "" {
		b.WriteString("\n\n" + p.Note)
	}
	return b.String()
}

func sortedHeaders(h map[string]string) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// hiddenToolGuard refuses a call for a name outside the surface with a
// deliberately ambiguous message: a client should not learn whether a tool
// exists in another workspace.
func hiddenToolGuard(names map[string]bool) sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "tools/call" {
				if r, ok := req.(*sdk.CallToolRequest); ok && !names[r.Params.Name] {
					// Deliberately ambiguous: a client must not learn whether a
					// tool exists in a workspace it cannot see.
					return nil, &jsonrpc.Error{Code: -32600, Message: "tool not available"}
				}
			}
			return next(ctx, method, req)
		}
	}
}

// recordMethod notes which JSON-RPC method is being served. The status
// the client sees is only known after the handler has written, and by then
// the method has been consumed with the body, so it is kept here.
func recordMethod() sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if s, _ := ctx.Value(surfaceKey).(*surface); s != nil {
				s.method = method
			}
			return next(ctx, method, req)
		}
	}
}

// routePattern is the matched chi pattern, for example /mcp/{server}.
func routePattern(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		return rc.RoutePattern()
	}
	return ""
}

func writeRPCError(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "error": map[string]any{"code": code, "message": msg}, "id": nil,
	})
}

func rpcCodeFor(status int) int {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return -32001
	default:
		return -32603
	}
}
