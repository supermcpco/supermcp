// Package mcp serves the Streamable HTTP endpoint clients connect to.
//
// The tool surface is computed per request, because it depends on who is
// calling: the server's connectors, filtered by the caller's permissions.
// tools/list is answered from that surface, and tools/call re-checks the
// name against it so a client cannot invoke something it was never shown.
//
// A server is stateless or stateful. Stateless answers every request on
// its own, on any replica. Stateful keeps a session per client on the
// replica that initialised it (sessions.go); the surface, the permission
// check and the caller are still those of each request, not of the one
// that opened the session.
package mcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/governance"
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
	// Sessions bounds the sessions kept for servers set to stateful.
	Sessions SessionOptions
	// Approvals is where the answer goes when the person behind a client
	// is asked about a call held for approval (elicit.go). Nil asks
	// nothing.
	Approvals *governance.Approvals
	// Audit records a request withdrawn from a client. Nil records
	// nothing.
	Audit audit.Sink
	// ElicitationTimeout bounds how long a held call waits for that
	// answer. Zero means one minute.
	ElicitationTimeout time.Duration
}

// Endpoint is the MCP HTTP handler.
type Endpoint struct {
	Deps
	// stateless serves the servers that keep nothing between requests,
	// stateful the ones that keep a session per client.
	stateless *sdk.StreamableHTTPHandler
	stateful  *sdk.StreamableHTTPHandler
	sessions  *sessionTable
	// requests holds the context of every stateful request in flight,
	// under the reference serve puts in a header of it. A session's
	// handlers run in the context of the request that opened the session;
	// this is how they reach the one that carried the message instead.
	requests sync.Map
	// draining is closed when the server starts to stop; a call waiting
	// on a person's answer stops waiting.
	draining  chan struct{}
	drainOnce sync.Once

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
	srv      *sdk.Server
	names    map[string]bool
	byName   map[string]visibleTool
	followUp bool
	expires  time.Time
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
	// byName is the same tools by name. A stateful session runs a call
	// with the tool as this request sees it, not as it stood when the
	// session was opened.
	byName map[string]visibleTool
	// followUp is whether the server lists the approval tools
	// (systemtools.go): whether any rule asking for a person reaches it.
	followUp bool
	// mcp is the assembled server, shared with every other request that
	// sees the same tools. nil until getServer assembles it.
	mcp    *sdk.Server
	err    error
	status int
	// method is the JSON-RPC method this request carried, recorded on the
	// way in so the HTTP layer can label the request with it once it knows
	// the status the client was given. One surface serves one request,
	// which is why the middleware writing it takes the surface and not the
	// shared server. It is atomic because the SDK writes it from the
	// goroutine serving the message while the HTTP handler reads it after
	// the transport returns, and a drained or cancelled request lets the
	// two overlap.
	method atomic.Pointer[string]
}

// methodName is the recorded JSON-RPC method, or "" before one was seen.
func (s *surface) methodName() string {
	if m := s.method.Load(); m != nil {
		return *m
	}
	return ""
}

type visibleTool struct {
	tool      *connector.Tool
	connector *connector.Connector
	ann       tool.Annotations
}

// requestRefHeader carries the reference to a stateful request's context
// from serve to the handlers the session runs. serve sets it on every
// stateful request and removes it from every stateless one, so a client
// cannot supply one.
const requestRefHeader = "X-Supermcp-Request-Ref"

// New builds the endpoint.
func New(d Deps) *Endpoint {
	e := &Endpoint{Deps: d, sessions: newSessionTable(d.Sessions, d.Metrics, d.Log), draining: make(chan struct{})}
	e.stateless = sdk.NewStreamableHTTPHandler(e.getServer, &sdk.StreamableHTTPOptions{
		Stateless:                    true,
		JSONResponse:                 d.JSONResponse,
		Logger:                       d.Log,
		MaxRequestBodyBytes:          4 << 20,
		PropagateRequestCancellation: true,
	})
	// The SDK's own idle timeout is left off: the session table closes
	// idle sessions, so that it knows about every one it closes.
	e.stateful = sdk.NewStreamableHTTPHandler(e.getServer, &sdk.StreamableHTTPOptions{
		JSONResponse:        d.JSONResponse,
		Logger:              d.Log,
		MaxRequestBodyBytes: 4 << 20,
	})
	return e
}

// Sessions reports how many stateful sessions this replica holds.
func (e *Endpoint) Sessions() int { return e.sessions.len() }

// Close ends every stateful session and refuses new ones. The server
// calls it once the HTTP listener has shut down, so no request is still
// using a session when it goes; a client that comes back reaches another
// replica, is answered 404 for its old session, and initialises again.
func (e *Endpoint) Close() {
	if n := e.sessions.close(); n > 0 && e.Log != nil {
		e.Log.Info("closed MCP sessions on the way out", "sessions", n)
	}
}

// Routes mounts the endpoint.
func (e *Endpoint) Routes(r chi.Router) {
	r.Handle("/mcp/{server}", e.serve())
	r.Handle("/mcp/{server}/*", e.serve())
}

func (e *Endpoint) serve() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Neither mode offers a stream the server writes to on its own: a
		// stateless server has nothing to resume, and a stateful one sends
		// what it asks the client on the stream of the request that asked.
		// Answering 405 here keeps clients that probe with GET from hanging.
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
			e.Metrics.ObserveMCPRequest(routePattern(r), s.methodName(), s.status)
			return
		}
		// The pattern, never the server id: an endpoint label taken from
		// the URL would give every MCP server installed a series of its own.
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		e.dispatch(ww, r, s)
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}
		e.Metrics.ObserveMCPRequest(routePattern(r), s.methodName(), status)
	}
}

// dispatch hands a request whose surface has been built to the transport
// for its server's session mode.
func (e *Endpoint) dispatch(w http.ResponseWriter, r *http.Request, s *surface) {
	r = r.WithContext(context.WithValue(r.Context(), surfaceKey, s))
	if s.server.Sessions == mcpserver.SessionsStateful {
		e.serveStateful(w, r, s)
		return
	}
	r.Header.Del(requestRefHeader)
	e.stateless.ServeHTTP(w, r)
}

// serveStateful serves one request to a server that keeps sessions.
//
// A request naming a session has to name one this replica holds for this
// server and this caller; anything else is answered 404, which is what
// tells a client to initialise again. A request naming none has to be an
// initialise, and takes a place in the session table.
func (e *Endpoint) serveStateful(w http.ResponseWriter, r *http.Request, s *surface) {
	p, _ := authz.From(r.Context())
	owner := ownerOf(p)
	ref := rand.Text()
	r.Header.Set(requestRefHeader, ref)
	e.requests.Store(ref, r.Context())
	defer e.requests.Delete(ref)

	if id := r.Header.Get(sessionHeader); id != "" {
		if !e.sessions.begin(id, s.server.ID, owner) {
			writeRPCError(w, http.StatusNotFound, -32001, "Session not found; initialize a new one")
			return
		}
		defer e.sessions.end(id)
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		e.stateful.ServeHTTP(ww, r)
		if r.Method == http.MethodDelete && ww.Status() == http.StatusNoContent {
			e.sessions.forget(id, telemetry.SessionClosedClient)
		}
		return
	}

	if r.Method != http.MethodPost {
		writeRPCError(w, http.StatusBadRequest, -32000, "Bad Request: "+r.Method+" needs an "+sessionHeader+" header")
		return
	}
	if init, err := isInitialize(r); err != nil {
		writeRPCError(w, http.StatusBadRequest, -32700, "Parse error")
		return
	} else if !init {
		// The transport says a server that needs a session answers 400 to
		// anything but an initialise that arrives without one.
		writeRPCError(w, http.StatusBadRequest, -32000, "Bad Request: this server keeps sessions; send initialize first and then the "+sessionHeader+" it answers with")
		return
	}
	if err := e.sessions.reserve(owner, p.OrgID); err != nil {
		w.Header().Set("Retry-After", "1")
		status := http.StatusServiceUnavailable
		if errors.Is(err, errCallerFull) || errors.Is(err, errOrgFull) {
			status = http.StatusTooManyRequests
		}
		writeRPCError(w, status, -32000, err.Error())
		return
	}
	var created string
	// Deferred, so a panic while initialising cannot leave the place
	// reserved, or the session marked busy, for ever.
	defer func() { e.sessions.settle(owner, p.OrgID, created) }()
	hook := &headerHook{ResponseWriter: w, hook: func(h http.Header, code int) {
		if id := h.Get(sessionHeader); id != "" && code < 300 {
			created = id
			e.sessions.add(id, s.server.ID, owner, p.OrgID, s.mcp)
		}
	}}
	e.stateful.ServeHTTP(hook, r)
}

// isInitialize reports whether the request's body is an initialise
// request, and puts the body back for the transport to read.
func isInitialize(r *http.Request) (bool, error) {
	if r.Body == nil {
		return false, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20+1))
	if err != nil {
		return false, fmt.Errorf("read request body: %w", err)
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	var msg struct {
		Method string `json:"method"`
	}
	// A batch or anything else that is not one object is not an
	// initialise; the transport has its own answer for a body it cannot
	// parse, so only a body that is not JSON at all is refused here.
	if err := json.Unmarshal(body, &msg); err != nil {
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) {
			return false, err
		}
		return false, nil
	}
	return msg.Method == "initialize", nil
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
		return &surface{server: srv, names: b.names, byName: b.byName, followUp: b.followUp, mcp: b.srv}
	}

	sf, err := e.Servers.Surface(ctx, srv)
	if err != nil {
		return &surface{err: err, status: http.StatusInternalServerError}
	}
	out := &surface{server: srv, names: map[string]bool{}, byName: map[string]visibleTool{}}
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
		vt := visibleTool{tool: st.Tool, connector: st.Connector, ann: ann}
		out.tools = append(out.tools, vt)
		out.byName[st.Tool.Name] = vt
	}
	out.instructionsText = sf.Instructions
	if e.Approvals != nil {
		connectors, tools := map[string]bool{}, make([]string, 0, len(out.tools))
		for _, vt := range out.tools {
			connectors[vt.connector.ID] = true
			tools = append(tools, vt.tool.ID)
		}
		out.followUp, err = e.Approvals.Reaches(ctx, srv.OrgID, srv.ID, sortedKeys(connectors), tools)
		if err != nil {
			return &surface{err: err, status: http.StatusInternalServerError}
		}
	}
	out.mcp = e.assemble(out)
	e.keepServer(key, &builtServer{srv: out.mcp, names: out.names, byName: out.byName, followUp: out.followUp,
		expires: time.Now().Add(builtTTL)})
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
	if s.followUp {
		for _, t := range systemTools() {
			srv.AddTool(t, e.systemToolHandler(s.server))
		}
	}
	// bindRequest is outermost, so everything after it reads the request
	// that carried the message. recordMethod is next, so a call the guard
	// refuses is still labelled with the method it asked for. Both read
	// the per-request surface out of the context, because this server
	// outlives the request. The system tools are answered after the guard
	// has let them through, and before the SDK looks for a registration a
	// server that does not list them does not have.
	srv.AddReceivingMiddleware(e.bindRequest(), recordMethod(), hiddenToolGuard(s.names), e.systemToolCalls(s.server))
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
func (e *Endpoint) handlerFor(server *mcpserver.Server, assembled visibleTool) sdk.ToolHandler {
	return func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		// The tool as this request sees it. On a stateless server that is
		// the one assembled; a stateful session was assembled when it
		// opened, and a tool edited since runs as it is now.
		vt := assembled
		if s, _ := ctx.Value(surfaceKey).(*surface); s != nil {
			if cur, ok := s.byName[req.Params.Name]; ok {
				vt = cur
			}
		}
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
		result := &sdk.CallToolResult{Content: out.Content, StructuredContent: out.Structured, IsError: out.IsError}
		if notice, ok := out.Structured.(*governance.Notice); ok {
			if s, _ := ctx.Value(surfaceKey).(*surface); s != nil && s.followUp && notice.State == governance.StatePending {
				result.Content = []sdk.Content{&sdk.TextContent{Text: textOf(result) + followUpHint}}
			}
			result = e.confirmHeld(ctx, req, server, p, notice, result)
		}
		return result, nil
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

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
//
// The names are the request's own surface where there is one: a stateful
// session outlives the surface it was opened with, and a tool taken away
// since must not stay callable on it. The system tools pass whether or
// not the server lists them; they only ever act on the caller's own
// requests.
//
// tools/list is held to the same names: a stateful session answers it from
// the server assembled when it opened, which may list a tool the caller
// has since lost, or that a narrower credential on the same session was
// never allowed. Tools added since are not added; the client sees them
// once it opens a new session.
func hiddenToolGuard(assembled map[string]bool) sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			names, followUp := assembled, true
			if s, _ := ctx.Value(surfaceKey).(*surface); s != nil && s.names != nil {
				names, followUp = s.names, s.followUp
			}
			switch method {
			case "tools/call":
				if r, ok := req.(*sdk.CallToolRequest); ok && !names[r.Params.Name] && !isSystemTool(r.Params.Name) {
					// Deliberately ambiguous: a client must not learn whether a
					// tool exists in a workspace it cannot see.
					return nil, &jsonrpc.Error{Code: -32600, Message: "tool not available"}
				}
			case "tools/list":
				res, err := next(ctx, method, req)
				if list, ok := res.(*sdk.ListToolsResult); ok && err == nil {
					list.Tools = visibleOnly(list.Tools, names, followUp)
				}
				return res, err
			}
			return next(ctx, method, req)
		}
	}
}

// visibleOnly drops the tools outside names. It copies only when it drops
// something, which on a stateless server it never does.
func visibleOnly(tools []*sdk.Tool, names map[string]bool, followUp bool) []*sdk.Tool {
	keep := func(t *sdk.Tool) bool {
		if isSystemTool(t.Name) {
			return followUp
		}
		return names[t.Name]
	}
	for i, t := range tools {
		if keep(t) {
			continue
		}
		out := append(make([]*sdk.Tool, 0, len(tools)-1), tools[:i]...)
		for _, t := range tools[i+1:] {
			if keep(t) {
				out = append(out, t)
			}
		}
		return out
	}
	return tools
}

// bindRequest runs a stateful session's handlers in the request that
// carried the message. The SDK runs them in the context of the request
// that opened the session, which would name that request's caller and
// surface for as long as the session lasts.
//
// Once bound, a handler reads every value from the current request, and
// from the session only the SDK's own (the id that routes what a handler
// sends back to the right stream); nothing of the opener's leaks through
// a key the request happens not to carry. It is cancelled when either
// the session or the request ends, and carries the request's deadline, so
// the router's timeout and a client that goes away reach the tool call,
// the data-loss screen and a question waiting on an answer. A stateless
// request carries no reference and passes through untouched.
func (e *Endpoint) bindRequest() sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			extra := req.GetExtra()
			if extra == nil || extra.Header == nil {
				return next(ctx, method, req)
			}
			ref := extra.Header.Get(requestRefHeader)
			if ref == "" {
				return next(ctx, method, req)
			}
			v, ok := e.requests.Load(ref)
			if !ok {
				// The request has already been answered: the transport
				// acknowledges a notification before handling it. Nothing
				// about a notification needs a caller, so it gets none, and
				// no surface.
				if strings.HasPrefix(method, "notifications/") {
					none := context.WithValue(authz.WithPrincipal(context.Background(), nil), surfaceKey, (*surface)(nil))
					return next(boundContext{Context: ctx, values: none}, method, req) //nolint:contextcheck // ctx's cancellation, and no values but the SDK's
				}
				return nil, &jsonrpc.Error{Code: -32600, Message: "the request carrying this message has ended"}
			}
			reqCtx, _ := v.(context.Context)
			bound, cancel := bindTo(ctx, reqCtx)
			defer cancel()
			return next(bound, method, req)
		}
	}
}

// bindTo derives the context a handler runs in from the session's and the
// request's: done when either is, with the request's deadline, and the
// request's values.
//
// The deadline sits beneath the cancellation, and a request that ended
// because its deadline passed is left to that deadline rather than
// cancelled: a context cancelled by hand reports Canceled whatever the
// cause, and a handler told its call was cancelled cannot tell the
// router's timeout from a client that went away.
func bindTo(session, request context.Context) (context.Context, context.CancelFunc) {
	base, cancelDeadline := session, context.CancelFunc(func() {})
	deadline, hasDeadline := request.Deadline()
	if hasDeadline {
		base, cancelDeadline = context.WithDeadline(session, deadline)
	}
	ctx, cancel := context.WithCancelCause(base)
	stop := context.AfterFunc(request, func() {
		if hasDeadline && errors.Is(request.Err(), context.DeadlineExceeded) {
			// The same deadline is about to end base, and that is how
			// the handler should hear of it.
			return
		}
		cancel(context.Cause(request))
	})
	return boundContext{Context: ctx, values: request}, func() {
		stop()
		cancel(context.Canceled)
		cancelDeadline()
	}
}

// boundContext is a handler's context once its request is known: the
// session's cancellation, the request's values, and of the session's
// values only the SDK's own.
type boundContext struct {
	context.Context
	values context.Context
}

// Value reads the request, and the session only for a key the SDK owns.
func (c boundContext) Value(key any) any {
	if v := c.values.Value(key); v != nil {
		return v
	}
	if sdkKey(key) {
		return c.Context.Value(key)
	}
	return nil
}

// sdkKey reports whether a context key is one of the MCP SDK's own, which
// it sets on the session's context and nowhere else.
func sdkKey(key any) bool {
	t := reflect.TypeOf(key)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t != nil && strings.HasPrefix(t.PkgPath(), "github.com/modelcontextprotocol/go-sdk/")
}

// recordMethod notes which JSON-RPC method is being served. The status
// the client sees is only known after the handler has written, and by then
// the method has been consumed with the body, so it is kept here.
func recordMethod() sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if s, _ := ctx.Value(surfaceKey).(*surface); s != nil {
				s.method.Store(&method)
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
