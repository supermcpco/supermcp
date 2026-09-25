// Package httpapi wires the HTTP surface: the admin API (huma on chi with
// generated OpenAPI), health endpoints, the public catalog and, later, the
// MCP endpoint and the embedded UI.
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/catalog"
	"github.com/supermcpco/supermcp/internal/config"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/dlp"
	"github.com/supermcpco/supermcp/internal/governance"
	"github.com/supermcpco/supermcp/internal/hardening"
	"github.com/supermcpco/supermcp/internal/httpclient"
	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/identity/saml"
	"github.com/supermcpco/supermcp/internal/identity/sso"
	"github.com/supermcpco/supermcp/internal/invoke"
	mcpendpoint "github.com/supermcpco/supermcp/internal/mcp"
	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/mcpserver"
	"github.com/supermcpco/supermcp/internal/scim"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/telemetry"
	"github.com/supermcpco/supermcp/internal/tenant"
	"github.com/supermcpco/supermcp/internal/web"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// Deps are the services the router needs.
type Deps struct {
	Config     *config.Config
	Log        *slog.Logger
	Store      *store.Store
	Catalog    *catalog.Catalog
	DB         *tenant.DB
	Identity   *identity.Service
	Authz      *authz.Evaluator
	Keys       *mcpauth.Keys
	Connectors *connector.Service
	Servers    *mcpserver.Service
	MCP        *mcpendpoint.Endpoint
	OAuth      *mcpauth.OAuth
	SSO        *sso.Service
	SCIM       *scim.Service
	SAML       *saml.Service
	Revisions  *governance.Service
	// DLP is the data-loss policy reader the tool-call path uses. The
	// policy routes write through it so a change drops that cache at once
	// on this replica; nil builds a reader of their own.
	DLP     *dlp.Policies
	Limiter *hardening.Limiter
	// refusals bounds how many refused token requests one client can
	// put on the audit trail a minute. New fills it in.
	refusals *refusalBudget
	Budgets  hardening.Budgets
	Metrics  *telemetry.Metrics
	// Executor renders a tool call for the dry-run preview. The MCP
	// endpoint holds the same one for making calls.
	Executor *invoke.Executor
	// Blobs holds binary tool results that were too large to embed.
	Blobs invoke.BlobStore
	// ImportFetch retrieves an OpenAPI document by URL. It is the guarded
	// client, because the URL comes from whoever is importing.
	ImportFetch   *httpclient.Client
	Audit         *audit.Writer
	AuditReader   *audit.Reader
	AuditPolicies *audit.Policies
	// AuditRetention is the same sweep the hourly job runs, so the window
	// the API reports is the one the job applies.
	AuditRetention   *audit.Retention
	OpenRegistration bool
}

// New builds the router and returns the huma API for OpenAPI export.
func New(d Deps) (http.Handler, huma.API) {
	if d.refusals == nil {
		d.refusals = newRefusalBudget(nil)
	}
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(requestLogger(d.Log))
	r.Use(middleware.Recoverer)
	// Inside Recoverer, so a panic is counted as the 500 it becomes.
	r.Use(httpMetrics(d.Metrics))
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(securityHeaders)
	r.Use(requestContext)
	r.Use(d.authenticate)
	r.Use(passwordAgeGate)
	// After authenticate, because a budget is per identity and the
	// principal is what identifies one.
	r.Use(d.rateLimit)
	r.Use(csrf)

	// Health, outside the API prefix and unauthenticated.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	r.Get("/readyz", readyz(d))
	r.Get("/api/v1/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"version":%q}`+"\n", d.Config.Version)
	})

	cfg := huma.DefaultConfig("supermcp", d.Config.Version)
	cfg.Info.Description = "supermcp admin API. Turns REST, GraphQL, SQL, SOAP and MCP systems into MCP tools."
	cfg.OpenAPIPath = "/api/openapi"
	cfg.DocsPath = ""
	if d.Config.Dev {
		cfg.DocsPath = "/api/docs"
	}
	cfg.Servers = []*huma.Server{{URL: d.Config.PublicURL.String()}}
	cfg.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"session": {Type: "apiKey", In: "cookie", Name: SessionCookie},
		"apiKey":  {Type: "apiKey", In: "header", Name: "X-API-Key"},
	}
	cfg.Transformers = append([]huma.Transformer{logKeyServiceErrors(d.Log)}, cfg.Transformers...)
	api := humachi.New(r, cfg)

	registerCatalog(api, d.Catalog)
	d.registerRoutes(api)
	d.connectorRoutes(api)
	d.resyncRoutes(api)
	d.toolRoutes(api)
	d.importRoutes(api)
	d.serverRoutes(api)
	d.keyRoutes(api)
	d.invocationRoutes(api)
	d.securityRoutes(api)
	d.reauthRoutes(api)
	d.ssoRoutes(api)
	d.auditRoutes(api)
	d.revisionRoutes(api)
	d.SAMLRoutes(api, d.SAML)
	d.dryRunRoutes(api)
	d.exporterRoutes(api)
	d.dlpRoutes(api)
	d.approvalRoutes(api)
	d.roleRoutes(api)
	d.memberRoutes(api)
	d.inviteRoutes(api)
	d.blobRoutes(api)
	d.connectorAuthRoutes(api)

	if d.OAuth != nil {
		d.oauthRoutes(r)
	}
	if d.SSO != nil {
		d.ssoBrowserRoutes(r)
	}
	if d.SAML != nil {
		d.SAMLBrowserRoutes(r, d.SAML)
	}
	// Connecting a connector to a vendor ends in a browser redirect back
	// here, like single sign-on does.
	d.connectorAuthBrowserRoutes(r)

	// SCIM speaks its own media type and error shape, so it is mounted
	// beside the API rather than described by it.
	if d.SCIM != nil {
		d.SCIM.Routes(r)
	}
	// MCP endpoint: an API key or an OAuth access token.
	if d.MCP != nil {
		d.MCP.Routes(r)
	}

	// Adapter JSON Schema for editors.
	r.Get("/schema/adapter/v2.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/schema+json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(adapter.JSONSchema)
	})

	// Embedded UI with SPA fallback; API and well-known paths never fall
	// through to it.
	r.NotFound(web.Handler())

	return r, api
}

// appCSP is the policy the interface is built to satisfy. The scripts and
// styles are hashed files served from this origin, so nothing needs an
// inline allowance; connect-src is self because the interface talks only
// to this API; and a page that loads no frames and may not be framed
// removes clickjacking and most injection paths at once. The policy is
// enforced rather than reported: an interface that would violate it is a
// bug to fix before release, not a statistic to collect.
const appCSP = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self' data: https:; " +
	"font-src 'self' data:; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		// The consent pages set their own, stricter policy; they are the
		// one surface an MCP client renders mid-flow.
		if !strings.HasPrefix(r.URL.Path, "/oauth/") {
			h.Set("Content-Security-Policy", appCSP)
		}
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func requestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			path := loggedPath(r.URL.Path)
			if ww.Status() >= 500 {
				log.Error("http server error",
					"req_id", middleware.GetReqID(r.Context()),
					"method", r.Method, "path", path, "status", ww.Status())
			}
			log.Info("http",
				"req_id", middleware.GetReqID(r.Context()),
				"method", r.Method,
				"path", path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
				"ip", r.RemoteAddr,
			)
		})
	}
}

// loggedPath is the request path as the access log records it. An
// invitation is accepted by opening /invite/<token> in a browser, and the
// token is the whole secret, so that one path is logged with the token
// replaced. The API calls that follow carry it in a body and are safe.
func loggedPath(p string) string {
	if rest, ok := strings.CutPrefix(p, "/invite/"); ok && rest != "" {
		return "/invite/{token}"
	}
	return p
}

// readyz fails when the database is unreachable or the schema is older
// than this binary expects, so a rolling upgrade never serves traffic from
// a pod whose migration hook has not finished.
func readyz(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "text/plain")
		if d.Store == nil {
			http.Error(w, "no database", http.StatusServiceUnavailable)
			return
		}
		if err := d.Store.App.Ping(ctx); err != nil {
			http.Error(w, "database: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		have, err := d.Store.SchemaVersion(ctx)
		if err != nil {
			http.Error(w, "schema: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		want, err := store.LatestVersion()
		if err != nil {
			http.Error(w, "schema: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		if have < want {
			http.Error(w, fmt.Sprintf("schema behind: have %d, want %d", have, want), http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	}
}

// --- catalog ---------------------------------------------------------------

type catalogListInput struct {
	Region   string `query:"region" doc:"Filter by region code"`
	Category string `query:"category" doc:"Filter by category"`
	Auth     string `query:"auth" doc:"Filter by auth type"`
	Keyless  bool   `query:"keyless" doc:"Only adapters that need no credentials"`
	Q        string `query:"q" doc:"Case-insensitive substring match on slug, name and description"`
}

type catalogListOutput struct {
	ETag string `header:"ETag"`
	Body struct {
		CatalogHash string               `json:"catalogHash"`
		Count       int                  `json:"count"`
		Adapters    []adapter.IndexEntry `json:"adapters" nullable:"false"`
	}
}

type catalogGetInput struct {
	Slug string `path:"slug" pattern:"^[a-z0-9-]+$"`
}

// catalogGetOutput carries the adapter as pre-rendered JSON; the OpenAPI
// response schema points at the published adapter JSON Schema instead of
// letting huma introspect the yaml.Node-backed struct.
type catalogGetOutput struct {
	ContentType string `header:"Content-Type"`
	Body        []byte
}

type catalogYAMLOutput struct {
	ContentType string `header:"Content-Type"`
	Body        []byte
}

func registerCatalog(api huma.API, c *catalog.Catalog) {
	huma.Register(api, huma.Operation{
		OperationID: "catalog-list",
		Method:      http.MethodGet,
		Path:        "/api/v1/catalog",
		Summary:     "List catalog adapters",
		Tags:        []string{"catalog"},
	}, func(_ context.Context, in *catalogListInput) (*catalogListOutput, error) {
		out := &catalogListOutput{ETag: `"` + c.Index.CatalogHash + `"`}
		out.Body.CatalogHash = c.Index.CatalogHash
		q := strings.ToLower(in.Q)
		for _, e := range c.Index.Adapters {
			if in.Region != "" && e.Region != in.Region {
				continue
			}
			if in.Category != "" && e.Category != in.Category {
				continue
			}
			if in.Auth != "" && string(e.Auth) != in.Auth {
				continue
			}
			if in.Keyless && !e.Keyless {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(e.Slug+" "+e.Name+" "+e.Description), q) {
				continue
			}
			out.Body.Adapters = append(out.Body.Adapters, e)
		}
		if out.Body.Adapters == nil {
			out.Body.Adapters = []adapter.IndexEntry{}
		}
		out.Body.Count = len(out.Body.Adapters)
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "catalog-get",
		Method:      http.MethodGet,
		Path:        "/api/v1/catalog/{slug}",
		Summary:     "Get one adapter as JSON",
		Tags:        []string{"catalog"},
		Responses: map[string]*huma.Response{
			"200": {
				Description: "The adapter document",
				Content: map[string]*huma.MediaType{
					"application/json": {Schema: &huma.Schema{
						Type:                 huma.TypeObject,
						AdditionalProperties: true,
						Description:          "Adapter document conforming to " + adapter.SchemaURL,
					}},
				},
			},
		},
	}, func(_ context.Context, in *catalogGetInput) (*catalogGetOutput, error) {
		a, err := c.Get(in.Slug)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, huma.Error404NotFound("no adapter " + in.Slug)
		}
		if err != nil {
			return nil, err
		}
		raw, err := adapter.MarshalJSON(a)
		if err != nil {
			return nil, err
		}
		return &catalogGetOutput{ContentType: "application/json", Body: raw}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "catalog-get-yaml",
		Method:      http.MethodGet,
		Path:        "/api/v1/catalog/{slug}/adapter.yaml",
		Summary:     "Get one adapter as YAML",
		Tags:        []string{"catalog"},
	}, func(_ context.Context, in *catalogGetInput) (*catalogYAMLOutput, error) {
		raw, err := c.Raw(in.Slug)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, huma.Error404NotFound("no adapter " + in.Slug)
		}
		if err != nil {
			return nil, err
		}
		return &catalogYAMLOutput{ContentType: "application/yaml", Body: raw}, nil
	})
}
