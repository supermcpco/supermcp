package httpapi

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"time"

	"encoding/json"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/mcpserver"
	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/tenant"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// --- session ---------------------------------------------------------------

type registerInput struct {
	Body struct {
		Email    string `json:"email" format:"email"`
		Name     string `json:"name,omitempty"`
		Password string `json:"password" minLength:"12"`
		OrgName  string `json:"orgName,omitempty"`
	}
}

type sessionOutput struct {
	SetCookie string `header:"Set-Cookie"`
	Body      sessionBody
}

type sessionBody struct {
	User        *userDTO           `json:"user,omitempty"`
	Org         *orgDTO            `json:"organization,omitempty"`
	Orgs        []orgDTO           `json:"organizations,omitempty"`
	Permissions []authz.Permission `json:"permissions,omitempty"`
	Anonymous   bool               `json:"anonymous,omitempty"`
	// PasswordExpired says the password is past the workspace's maximum
	// age and has to be changed before anything else will work.
	PasswordExpired bool `json:"passwordExpired,omitempty"`
	Registered      bool `json:"registrationOpen,omitempty"`
	// SignIn says how this session signed in, and so how its holder is
	// asked to sign in again when an operation refuses it as stale.
	SignIn *signInDTO `json:"signIn,omitempty"`
}

type signInDTO struct {
	Method       string `json:"method" enum:"password,sso,saml" doc:"How the session signed in"`
	ProviderID   string `json:"providerId,omitempty" doc:"The single sign-on provider, for sso and saml"`
	ProviderName string `json:"providerName,omitempty" doc:"The provider's name, to put on the button that signs in again"`
	ReauthURL    string `json:"reauthUrl,omitempty" doc:"Where to send the browser to sign in again through the provider; append &next= to come back. Empty for a password session, which confirms its password with POST /api/v1/auth/reauth, and for a provider that cannot confirm a recent sign-in."`
	// CanReauth is false for a provider that never says when the person
	// authenticated (GitHub, plain OAuth2): signing in again through it
	// proves nothing about when, so it cannot make a session fresh.
	CanReauth bool `json:"canReauth" doc:"Whether this session can be made fresh again: by its password, or by a provider that says when the person authenticated"`
	// AuthenticatedAt and FreshUntil let a client warn before an action
	// rather than after; the server decides either way.
	AuthenticatedAt *time.Time `json:"authenticatedAt,omitempty" doc:"When the session last proved who is using it; absent when nobody vouched for the time"`
	FreshUntil      *time.Time `json:"freshUntil,omitempty" doc:"Until when sensitive operations are allowed without signing in again"`
}

type userDTO struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type orgDTO struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

func (d Deps) registerRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "register", Method: http.MethodPost, Path: "/api/v1/auth/register",
		Summary: "Create the first account, or a new account when open registration is enabled", Tags: []string{"auth"}},
		func(ctx context.Context, in *registerInput) (*sessionOutput, error) {
			u, o, err := d.Identity.Register(ctx, identity.RegisterInput{Email: in.Body.Email, Name: in.Body.Name, Password: in.Body.Password, OrgName: in.Body.OrgName})
			if err != nil {
				d.authEvent(ctx, "account.register", audit.Failure, in.Body.Email, map[string]any{"error": err.Error()})
				return nil, humaErr(err)
			}
			out, err := d.startSession(ctx, u, o)
			if err != nil {
				return nil, err
			}
			d.emit(ctx, audit.Event{OrgID: o.ID, Category: audit.CategoryAuth, Action: "account.register",
				Outcome: audit.Success, ActorKind: "user", ActorID: u.ID, ActorDisplay: u.Email,
				TargetKind: "organization", TargetID: o.ID, TargetDisplay: o.Name})
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "login", Method: http.MethodPost, Path: "/api/v1/auth/login",
		Summary: "Sign in with email and password", Tags: []string{"auth"}},
		func(ctx context.Context, in *struct {
			Body struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}
		}) (*sessionOutput, error) {
			ip, _ := ctx.Value(ipKey).(string)
			u, err := d.Identity.Login(ctx, in.Body.Email, in.Body.Password, ip)
			if err != nil {
				// A failed sign-in names the address that was tried, not an
				// account: there may not be one.
				d.authEvent(ctx, "session.create", audit.Failure, in.Body.Email, map[string]any{"reason": err.Error(), "method": "password"})
				return nil, humaErr(err)
			}
			orgs, err := d.Identity.Orgs(ctx, u.ID)
			if err != nil {
				return nil, err
			}
			var first *identity.Org
			if len(orgs) > 0 {
				first = &orgs[0]
			}
			out, err := d.startSession(ctx, u, first)
			if err != nil {
				return nil, err
			}
			orgID := ""
			if first != nil {
				orgID = first.ID
			}
			d.emit(ctx, audit.Event{OrgID: orgID, Category: audit.CategoryAuth, Action: "session.create",
				Outcome: audit.Success, ActorKind: "user", ActorID: u.ID, ActorDisplay: u.Email,
				Meta: map[string]any{"method": "password"}})
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "logout", Method: http.MethodPost, Path: "/api/v1/auth/logout",
		Summary: "End the current session", Tags: []string{"auth"}},
		func(ctx context.Context, _ *struct{}) (*sessionOutput, error) {
			if p, ok := authz.From(ctx); ok && p.SessionID != "" {
				// The cookie is cleared only once the session is over: a
				// sign-out that did not happen must not look as if it had.
				revoked, err := d.Identity.RevokeSession(ctx, p.SessionID, "logout")
				if err != nil {
					d.emit(ctx, audit.Event{Category: audit.CategoryAuth, Action: "session.end", Outcome: audit.Failure,
						Meta: map[string]any{"error": err.Error()}})
					return nil, huma.Error500InternalServerError("could not end the session; try again")
				}
				d.emit(ctx, audit.Event{Category: audit.CategoryAuth, Action: "session.end", Outcome: audit.Success,
					Meta: map[string]any{"revokedTokens": revoked}})
			}
			out := &sessionOutput{Body: sessionBody{Anonymous: true}}
			out.SetCookie = d.clearCookie()
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "session", Method: http.MethodGet, Path: "/api/v1/auth/session",
		Summary: "Describe the current session", Tags: []string{"auth"}},
		func(ctx context.Context, _ *struct{}) (*sessionOutput, error) {
			p, ok := authz.From(ctx)
			if !ok || p.AuthMethod != "session" {
				// A fresh instance allows the first registration however this is
				// set, and the screen has no way to offer it unless it is told.
				open := d.Config.Dev || d.OpenRegistration || d.Identity.Unclaimed(ctx)
				return &sessionOutput{Body: sessionBody{Anonymous: true, Registered: open}}, nil
			}
			return d.sessionBodyFor(ctx, p)
		})

	huma.Register(api, huma.Operation{OperationID: "switch-org", Method: http.MethodPost, Path: "/api/v1/auth/switch-org",
		Summary: "Switch the active organisation", Tags: []string{"auth"}},
		func(ctx context.Context, in *struct {
			Body struct {
				OrganizationID string `json:"organizationId"`
			}
		}) (*sessionOutput, error) {
			p, ok := authz.From(ctx)
			if !ok || p.SessionID == "" {
				return nil, huma.Error401Unauthorized("authentication required")
			}
			sess, err := d.Identity.LoadSession(ctx, p.SessionID)
			if err != nil {
				return nil, humaErr(err)
			}
			if err := d.Identity.SwitchOrg(ctx, sess, in.Body.OrganizationID); err != nil {
				d.emit(ctx, audit.Event{Category: audit.CategoryAuth, Action: "session.switch_org", Outcome: audit.Denied,
					TargetKind: "organization", TargetID: in.Body.OrganizationID, Meta: map[string]any{"reason": err.Error()}})
				return nil, huma.Error403Forbidden(err.Error())
			}
			d.emit(ctx, audit.Event{OrgID: in.Body.OrganizationID, Category: audit.CategoryAuth,
				Action: "session.switch_org", Outcome: audit.Success,
				TargetKind: "organization", TargetID: in.Body.OrganizationID})
			p.OrgID = in.Body.OrganizationID
			return d.sessionBodyFor(ctx, p)
		})
}

func (d Deps) startSession(ctx context.Context, u *identity.User, o *identity.Org) (*sessionOutput, error) {
	orgID := ""
	if o != nil {
		orgID = o.ID
	}
	ip, _ := ctx.Value(ipKey).(string)
	ua, _ := ctx.Value(uaKey).(string)
	sess, err := d.Identity.CreateSession(ctx, u.ID, orgID, "password", "", time.Now(), ip, ua)
	if err != nil {
		return nil, err
	}
	p := d.Identity.Principal(sess, u.Email)
	d.markPasswordAge(ctx, sess, p)
	out, err := d.sessionBodyFor(ctx, p)
	if err != nil {
		return nil, err
	}
	out.SetCookie = d.cookieValue(sess.Secret, int(d.Identity.Cfg.SessionAbsolute/time.Second))
	return out, nil
}

func (d Deps) sessionBodyFor(ctx context.Context, p *authz.Principal) (*sessionOutput, error) {
	out := &sessionOutput{}
	out.Body.PasswordExpired = p.PasswordExpired
	out.Body.SignIn = d.signInFor(ctx, p)
	orgs, err := d.Identity.Orgs(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	for _, o := range orgs {
		dto := orgDTO{ID: o.ID, Slug: o.Slug, Name: o.Name}
		out.Body.Orgs = append(out.Body.Orgs, dto)
		if o.ID == p.OrgID {
			cp := dto
			out.Body.Org = &cp
		}
	}
	u, err := d.Identity.UserByID(tenant.WithOrg(ctx, p.OrgID), p.OrgID, p.ID)
	if err == nil {
		out.Body.User = &userDTO{ID: u.ID, Email: u.Email, Name: u.Name}
	} else {
		out.Body.User = &userDTO{ID: p.ID, Email: p.Email}
	}
	if p.OrgID != "" {
		perms, err := d.Authz.EffectivePermissions(tenant.WithOrg(ctx, p.OrgID), p)
		if err != nil {
			return nil, err
		}
		out.Body.Permissions = perms
	}
	return out, nil
}

func (d Deps) cookieValue(id string, maxAge int) string {
	secure := ""
	if d.Config.PublicURL != nil && d.Config.PublicURL.Scheme == "https" {
		secure = "; Secure"
	}
	return d.cookieName() + "=" + id + "; Path=/; HttpOnly; SameSite=Lax" + secure + "; Max-Age=" + itoa(maxAge)
}

func (d Deps) clearCookie() string {
	return d.cookieName() + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
}

// --- connectors ------------------------------------------------------------

func (d Deps) connectorRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "connectors-list", Method: http.MethodGet, Path: "/api/v1/connectors",
		Summary: "List connectors", Tags: []string{"connectors"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct {
			Body []connectorDTO `json:"body"`
		}, error) {
			p, err := d.require(ctx, authz.ConnectorsRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			list, err := d.Connectors.List(ctx, p.OrgID)
			if err != nil {
				return nil, err
			}
			return &struct {
				Body []connectorDTO `json:"body"`
			}{Body: d.connectorsDTO(list)}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "connectors-get", Method: http.MethodGet, Path: "/api/v1/connectors/{id}",
		Summary: "Get a connector", Tags: []string{"connectors"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct{ Body connectorDTO }, error) {
			p, err := d.require(ctx, authz.ConnectorsRead, authz.Resource{ConnectorID: in.ID})
			if err != nil {
				return nil, err
			}
			c, err := d.Connectors.Get(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, humaErr(err)
			}
			return &struct{ Body connectorDTO }{Body: d.connectorDTO(c)}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "connectors-install", Method: http.MethodPost, Path: "/api/v1/connectors/install",
		Summary: "Install a catalog adapter as a connector", Tags: []string{"connectors"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			Body struct {
				Slug        string            `json:"slug"`
				Credentials map[string]string `json:"credentials,omitempty"`
			}
		}) (*struct{ Body connectorDTO }, error) {
			p, err := d.require(ctx, authz.ConnectorsCreate, authz.Resource{})
			if err != nil {
				return nil, err
			}
			a, err := d.Catalog.Get(in.Body.Slug)
			if err != nil {
				return nil, huma.Error404NotFound("no adapter " + in.Body.Slug)
			}
			entry, _ := d.Catalog.Entry(in.Body.Slug)
			c, err := d.Connectors.Install(ctx, p.OrgID, a, entry.ContentHash, in.Body.Credentials, p.ID)
			if err != nil {
				d.adminFailed(ctx, "connector.install", "connector", in.Body.Slug, err)
				return nil, humaErr(err)
			}
			dto := d.connectorDTO(c)
			d.admin(ctx, "connector.install", "connector", c.ID, c.Name, audit.Created(dto))
			return &struct{ Body connectorDTO }{Body: dto}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "connectors-credentials", Method: http.MethodPut, Path: "/api/v1/connectors/{id}/credentials",
		Summary: "Set or clear connector credentials", Tags: []string{"connectors"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID   string `path:"id"`
			Body struct {
				Credentials     map[string]string `json:"credentials"`
				ExpectedVersion int64             `json:"expectedVersion,omitempty" minimum:"0" doc:"The connector version that was read. A mismatch is a 409. Optional for now; a later release requires it"`
			}
		}) (*struct{ Body connectorDTO }, error) {
			p, err := d.requireFresh(ctx, authz.ConnectorsAuth, authz.Resource{ConnectorID: in.ID})
			if err != nil {
				return nil, err
			}
			if err := d.Connectors.SetCredentials(ctx, p.OrgID, in.ID, in.Body.Credentials, in.Body.ExpectedVersion); err != nil {
				d.adminFailed(ctx, "connector.credentials.update", "connector", in.ID, err)
				return nil, humaErr(err)
			}
			c, err := d.Connectors.Get(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, humaErr(err)
			}
			// The values never reach the stream; which credentials were set
			// is the part an auditor needs.
			names := make([]string, 0, len(in.Body.Credentials))
			for name := range in.Body.Credentials {
				names = append(names, name)
			}
			sort.Strings(names)
			d.emit(ctx, audit.Event{Category: audit.CategorySecrets, Action: "connector.credentials.update",
				Outcome: audit.Success, TargetKind: "connector", TargetID: c.ID, TargetDisplay: c.Name,
				Meta: map[string]any{"credentials": names}})
			return &struct{ Body connectorDTO }{Body: d.connectorDTO(c)}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "connectors-update", Method: http.MethodPatch, Path: "/api/v1/connectors/{id}",
		Summary: "Update a connector", Tags: []string{"connectors"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID   string `path:"id"`
			Body struct {
				Name         *string `json:"name,omitempty"`
				Instructions *string `json:"instructions,omitempty"`
				ReadOnly     *bool   `json:"readOnly,omitempty"`
				Enabled      *bool   `json:"enabled,omitempty"`
				// ExpectedVersion is optional for one release, then required
				// as it is on a tool update.
				ExpectedVersion int64 `json:"expectedVersion,omitempty" minimum:"0" doc:"The connector version that was read. A mismatch is a 409. Optional for now; a later release requires it"`
			}
		}) (*struct{ Body connectorDTO }, error) {
			p, err := d.require(ctx, authz.ConnectorsUpdate, authz.Resource{ConnectorID: in.ID})
			if err != nil {
				return nil, err
			}
			before, _ := d.Connectors.Get(ctx, p.OrgID, in.ID)
			c, err := d.Connectors.Update(ctx, p.OrgID, in.ID, connector.UpdateInput{Name: in.Body.Name, Instructions: in.Body.Instructions,
				ReadOnly: in.Body.ReadOnly, Enabled: in.Body.Enabled, ExpectedVersion: in.Body.ExpectedVersion, ActorID: p.ID})
			if err != nil {
				d.adminFailed(ctx, "connector.update", "connector", in.ID, err)
				return nil, humaErr(err)
			}
			var was any
			if before != nil {
				was = d.connectorDTO(before)
			}
			dto := d.connectorDTO(c)
			d.admin(ctx, "connector.update", "connector", c.ID, c.Name, audit.Changes(was, dto))
			return &struct{ Body connectorDTO }{Body: dto}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "connectors-delete", Method: http.MethodDelete, Path: "/api/v1/connectors/{id}",
		Summary: "Delete a connector", Tags: []string{"connectors"}, Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct{}, error) {
			p, err := d.require(ctx, authz.ConnectorsDelete, authz.Resource{ConnectorID: in.ID})
			if err != nil {
				return nil, err
			}
			before, _ := d.Connectors.Get(ctx, p.OrgID, in.ID)
			if err := d.Connectors.Delete(ctx, p.OrgID, in.ID, p.ID); err != nil {
				d.adminFailed(ctx, "connector.delete", "connector", in.ID, err)
				return nil, humaErr(err)
			}
			name := ""
			var was any
			if before != nil {
				name, was = before.Name, d.connectorDTO(before)
			}
			d.admin(ctx, "connector.delete", "connector", in.ID, name, audit.Deleted(was))
			return &struct{}{}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "connectors-tools", Method: http.MethodGet, Path: "/api/v1/connectors/{id}/tools",
		Summary: "List a connector's tools", Tags: []string{"connectors"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct {
			Body []toolDTO `json:"body"`
		}, error) {
			p, err := d.require(ctx, authz.ToolsRead, authz.Resource{ConnectorID: in.ID})
			if err != nil {
				return nil, err
			}
			// The derived hints depend on the connector's transport and
			// read-only flag; it is read once for the whole list.
			c, err := d.Connectors.Get(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, humaErr(err)
			}
			tools, err := d.Connectors.Tools(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, humaErr(err)
			}
			out := make([]toolDTO, 0, len(tools))
			for _, t := range tools {
				out = append(out, toolToDTO(t, c))
			}
			return &struct {
				Body []toolDTO `json:"body"`
			}{Body: out}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "tools-enable", Method: http.MethodPatch, Path: "/api/v1/tools/{id}",
		Summary: "Enable or disable a tool", Tags: []string{"connectors"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID   string `path:"id"`
			Body struct {
				Enabled bool `json:"enabled"`
			}
		}) (*struct{ Body struct{ OK bool } }, error) {
			// The tool's connector is part of the resource, so a binding
			// scoped to the connector covers its tools.
			p, t, err := d.requireTool(ctx, authz.ToolsUpdate, in.ID)
			if err != nil {
				return nil, err
			}
			if err := d.Connectors.SetToolEnabled(ctx, p.OrgID, in.ID, in.Body.Enabled, p.ID); err != nil {
				d.adminFailed(ctx, "tool.visibility.update", "tool", in.ID, err)
				return nil, humaErr(err)
			}
			// Which tools an AI client can reach is a security decision, so
			// the change is recorded even though it edits one boolean.
			d.admin(ctx, "tool.visibility.update", "tool", in.ID, t.Name,
				audit.Changes(map[string]any{"enabled": t.Enabled}, map[string]any{"enabled": in.Body.Enabled}))
			return &struct{ Body struct{ OK bool } }{Body: struct{ OK bool }{true}}, nil
		})
}

// connectorDTO is the wire shape. Transport and auth are plain objects:
// the domain types wrap YAML nodes, which no JSON Schema generator can
// describe, and the UI only ever reads them. Both go through
// connector.RedactConfig, so this shape is safe for a response and for
// the audit diff alike.
type connectorDTO struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Transport    map[string]any `json:"transport" doc:"How the connector reaches its upstream. Passwords in URLs and connection strings read ***"`
	Auth         map[string]any `json:"auth" doc:"How the connector signs in. Secret values, such as passwords, tokens and client secrets, read ***; the stored values are unchanged"`
	Instructions string         `json:"instructions,omitempty"`
	CatalogSlug  string         `json:"catalogSlug,omitempty"`
	CatalogHash  string         `json:"catalogHash,omitempty"`
	// CatalogOutdated is set when the adapter this server carries differs
	// from the one the connector came from; see the resync routes.
	CatalogOutdated bool                       `json:"catalogOutdated" doc:"The adapter this server carries differs from the one the connector was installed or last re-synced from"`
	ReadOnly        bool                       `json:"readOnly"`
	Enabled         bool                       `json:"enabled"`
	Version         int64                      `json:"version" doc:"Send back as expectedVersion when updating"`
	ToolCount       int                        `json:"toolCount"`
	Credentials     []connector.CredentialInfo `json:"credentials"`
	CreatedAt       time.Time                  `json:"createdAt"`
	UpdatedAt       time.Time                  `json:"updatedAt"`
}

func connectorToDTO(c *connector.Connector) connectorDTO {
	d := connectorDTO{ID: c.ID, Name: c.Name, Instructions: c.Instructions, CatalogSlug: c.CatalogSlug,
		CatalogHash: c.CatalogHash, ReadOnly: c.ReadOnly, Enabled: c.Enabled, Version: c.Version,
		ToolCount: c.ToolCount, Credentials: c.Credentials, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
	if d.Credentials == nil {
		d.Credentials = []connector.CredentialInfo{}
	}
	d.Transport = redactedMap(c.Transport)
	d.Auth = redactedMap(c.Auth)
	return d
}

// redactedMap is a connector's auth or transport as a plain object, with
// its secrets redacted.
func redactedMap(v any) map[string]any {
	m, _ := connector.RedactConfig(toMap(v)).(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func toMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

// --- MCP servers -----------------------------------------------------------

func (d Deps) serverRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "servers-list", Method: http.MethodGet, Path: "/api/v1/servers",
		Summary: "List MCP servers", Tags: []string{"servers"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct {
			Body []*mcpserver.Server `json:"body"`
		}, error) {
			p, err := d.require(ctx, authz.ServersRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			list, err := d.Servers.List(ctx, p.OrgID)
			if err != nil {
				return nil, err
			}
			return &struct {
				Body []*mcpserver.Server `json:"body"`
			}{Body: list}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "servers-create", Method: http.MethodPost, Path: "/api/v1/servers",
		Summary: "Create an MCP server", Tags: []string{"servers"}, Security: sessionSecurity,
		Description: "A browser session must have signed in within the fresh-auth window: a new server is a new " +
			"endpoint for keys to reach its connectors through."},
		func(ctx context.Context, in *struct {
			Body struct {
				Name         string   `json:"name"`
				Slug         string   `json:"slug,omitempty"`
				Instructions string   `json:"instructions,omitempty"`
				ConnectorIDs []string `json:"connectorIds,omitempty"`
			}
		}) (*struct{ Body *mcpserver.Server }, error) {
			p, err := d.requireFresh(ctx, authz.ServersCreate, authz.Resource{})
			if err != nil {
				return nil, err
			}
			srv, err := d.Servers.Create(ctx, p.OrgID, in.Body.Name, in.Body.Slug, in.Body.Instructions, in.Body.ConnectorIDs, p.ID)
			if err != nil {
				d.adminFailed(ctx, "server.create", "server", "", err)
				return nil, humaErr(err)
			}
			d.admin(ctx, "server.create", "server", srv.ID, srv.Name, audit.Created(srv))
			return &struct{ Body *mcpserver.Server }{Body: srv}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "servers-get", Method: http.MethodGet, Path: "/api/v1/servers/{id}",
		Summary: "Get an MCP server", Tags: []string{"servers"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct{ Body *mcpserver.Server }, error) {
			p, err := d.require(ctx, authz.ServersRead, authz.Resource{ServerID: in.ID})
			if err != nil {
				return nil, err
			}
			srv, err := d.Servers.Get(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, humaErr(err)
			}
			return &struct{ Body *mcpserver.Server }{Body: srv}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "servers-update", Method: http.MethodPatch, Path: "/api/v1/servers/{id}",
		Summary: "Update an MCP server", Tags: []string{"servers"}, Security: sessionSecurity,
		Description: "Setting connectorIds, or enabled to true, widens what keys bound to the server can reach, so a " +
			"browser session must have signed in within the fresh-auth window to do either. A rename, new " +
			"instructions or turning the server off do not ask."},
		func(ctx context.Context, in *struct {
			ID   string `path:"id"`
			Body struct {
				Name         *string   `json:"name,omitempty"`
				Instructions *string   `json:"instructions,omitempty"`
				Enabled      *bool     `json:"enabled,omitempty"`
				ConnectorIDs *[]string `json:"connectorIds,omitempty"`
				// ExpectedVersion is optional for one release, then required
				// as it is on a tool update.
				ExpectedVersion int64 `json:"expectedVersion,omitempty" minimum:"0" doc:"The server version that was read. A mismatch is a 409. Optional for now; a later release requires it"`
			}
		}) (*struct{ Body *mcpserver.Server }, error) {
			r := authz.Resource{ServerID: in.ID}
			p, err := d.require(ctx, authz.ServersUpdate, r)
			if err != nil {
				return nil, err
			}
			if in.Body.ConnectorIDs != nil || (in.Body.Enabled != nil && *in.Body.Enabled) {
				if err := d.checkFresh(ctx, p, authz.ServersUpdate, r); err != nil {
					return nil, err
				}
			}
			before, _ := d.Servers.Get(ctx, p.OrgID, in.ID)
			srv, err := d.Servers.Update(ctx, p.OrgID, in.ID, mcpserver.UpdateInput{Name: in.Body.Name, Instructions: in.Body.Instructions,
				Enabled: in.Body.Enabled, ConnectorIDs: in.Body.ConnectorIDs, ExpectedVersion: in.Body.ExpectedVersion, ActorID: p.ID})
			if err != nil {
				d.adminFailed(ctx, "server.update", "server", in.ID, err)
				return nil, humaErr(err)
			}
			d.admin(ctx, "server.update", "server", srv.ID, srv.Name, audit.Changes(before, srv))
			return &struct{ Body *mcpserver.Server }{Body: srv}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "servers-delete", Method: http.MethodDelete, Path: "/api/v1/servers/{id}",
		Summary: "Delete an MCP server", Tags: []string{"servers"}, Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct{}, error) {
			p, err := d.require(ctx, authz.ServersDelete, authz.Resource{ServerID: in.ID})
			if err != nil {
				return nil, err
			}
			before, _ := d.Servers.Get(ctx, p.OrgID, in.ID)
			if err := d.Servers.Delete(ctx, p.OrgID, in.ID, p.ID); err != nil {
				d.adminFailed(ctx, "server.delete", "server", in.ID, err)
				return nil, humaErr(err)
			}
			name := ""
			if before != nil {
				name = before.Name
			}
			d.admin(ctx, "server.delete", "server", in.ID, name, audit.Deleted(before))
			return &struct{}{}, nil
		})
}

// --- API keys --------------------------------------------------------------

type apiKeyDTO struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes" nullable:"false"`
	ServerID   string     `json:"serverId,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

func keyDTO(k mcpauth.APIKey) apiKeyDTO {
	return apiKeyDTO{ID: k.ID, Name: k.Name, Prefix: k.Prefix, Scopes: k.Scopes, ServerID: k.ServerID,
		ExpiresAt: k.ExpiresAt, LastUsedAt: k.LastUsedAt, RevokedAt: k.RevokedAt, CreatedAt: k.CreatedAt}
}

func (d Deps) keyRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "keys-list", Method: http.MethodGet, Path: "/api/v1/api-keys",
		Summary: "List API keys", Tags: []string{"api-keys"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct {
			Body []apiKeyDTO `json:"body"`
		}, error) {
			p, err := d.require(ctx, authz.APIKeysSelf, authz.Resource{})
			if err != nil {
				return nil, err
			}
			all := d.Authz.Require(ctx, authz.APIKeysOrg, authz.Resource{}) == nil
			list, err := d.Keys.List(ctx, p.OrgID, p.ID, all)
			if err != nil {
				return nil, err
			}
			out := make([]apiKeyDTO, 0, len(list))
			for _, k := range list {
				out = append(out, keyDTO(k))
			}
			return &struct {
				Body []apiKeyDTO `json:"body"`
			}{Body: out}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "keys-create", Method: http.MethodPost, Path: "/api/v1/api-keys",
		Summary: "Create an API key (the secret is shown once)", Tags: []string{"api-keys"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			Body struct {
				Name     string   `json:"name"`
				Scopes   []string `json:"scopes,omitempty"`
				ServerID string   `json:"serverId,omitempty"`
				TTLDays  int      `json:"ttlDays,omitempty"`
			}
		}) (*struct {
			Body struct {
				Key    apiKeyDTO `json:"key"`
				Secret string    `json:"secret"`
			}
		}, error) {
			p, err := d.requireFresh(ctx, authz.APIKeysSelf, authz.Resource{})
			if err != nil {
				return nil, err
			}
			ttl := time.Duration(in.Body.TTLDays) * 24 * time.Hour
			rec, secret, err := d.Keys.Create(ctx, mcpauth.CreateInput{OrgID: p.OrgID, PrincipalKind: "user", PrincipalID: p.ID,
				Name: in.Body.Name, Scopes: in.Body.Scopes, ServerID: in.Body.ServerID, TTL: ttl, CreatedBy: p.ID})
			if err != nil {
				d.adminFailed(ctx, "apikey.create", "api_key", "", err)
				return nil, humaErr(err)
			}
			// The secret is not in the diff: only its prefix, scopes and
			// expiry, which is what tells an auditor how far the key reaches.
			d.emit(ctx, audit.Event{Category: audit.CategorySecrets, Action: "apikey.create", Outcome: audit.Success,
				TargetKind: "api_key", TargetID: rec.ID, TargetDisplay: rec.Name,
				Diff: audit.Created(keyDTO(*rec))})
			out := &struct {
				Body struct {
					Key    apiKeyDTO `json:"key"`
					Secret string    `json:"secret"`
				}
			}{}
			out.Body.Key, out.Body.Secret = keyDTO(*rec), secret
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "keys-revoke", Method: http.MethodDelete, Path: "/api/v1/api-keys/{id}",
		Summary: "Revoke an API key", Tags: []string{"api-keys"}, Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct{}, error) {
			p, err := d.requireFresh(ctx, authz.APIKeysSelf, authz.Resource{})
			if err != nil {
				return nil, err
			}
			self := d.Authz.Require(ctx, authz.APIKeysOrg, authz.Resource{}) != nil
			if err := d.Keys.Revoke(ctx, p.OrgID, in.ID, p.ID, self, "revoked by user"); err != nil {
				d.adminFailed(ctx, "apikey.revoke", "api_key", in.ID, err)
				return nil, humaErr(err)
			}
			d.emit(ctx, audit.Event{Category: audit.CategorySecrets, Action: "apikey.revoke", Outcome: audit.Success,
				TargetKind: "api_key", TargetID: in.ID})
			return &struct{}{}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "keys-rotate", Method: http.MethodPost, Path: "/api/v1/api-keys/{id}/rotate",
		Summary:     "Rotate an API key (the new secret is shown once)",
		Description: "Creates a replacement with the same name, scopes and server, and brings the old key's expiry forward to now plus the grace period (never later than it already was). Both happen together or not at all.",
		Tags:        []string{"api-keys"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID   string `path:"id"`
			Body struct {
				GraceSeconds *int `json:"graceSeconds,omitempty" minimum:"0" maximum:"604800" doc:"How long the old key keeps working, in seconds. 0 stops it at once; omitted means 86400 (24 hours)."`
			}
		}) (*struct{ Body rotatedKeyDTO }, error) {
			p, err := d.requireFresh(ctx, authz.APIKeysSelf, authz.Resource{})
			if err != nil {
				return nil, err
			}
			self := d.Authz.Require(ctx, authz.APIKeysOrg, authz.Resource{}) != nil
			grace := mcpauth.DefaultRotationGrace
			if in.Body.GraceSeconds != nil {
				grace = time.Duration(*in.Body.GraceSeconds) * time.Second
			}
			rot, err := d.Keys.Rotate(ctx, mcpauth.RotateInput{OrgID: p.OrgID, ID: in.ID, ActorID: p.ID, Self: self, Grace: grace})
			if err != nil {
				d.adminFailed(ctx, "apikey.rotate", "api_key", in.ID, err)
				return nil, humaErr(err)
			}
			// As with create, the secret stays out of the event: the
			// replacement's prefix, scopes and expiry and the old key's new
			// expiry say what changed.
			d.emit(ctx, audit.Event{Category: audit.CategorySecrets, Action: "apikey.rotate", Outcome: audit.Success,
				TargetKind: "api_key", TargetID: in.ID, TargetDisplay: rot.Key.Name,
				Diff: audit.Created(keyDTO(*rot.Key)),
				Meta: map[string]any{"replacementId": rot.Key.ID, "previousExpiresAt": rot.PreviousExpiresAt, "graceSeconds": int64(grace / time.Second)}})
			return &struct{ Body rotatedKeyDTO }{Body: rotatedKeyDTO{Key: keyDTO(*rot.Key), Secret: rot.Secret,
				PreviousKeyID: in.ID, PreviousExpiresAt: rot.PreviousExpiresAt}}, nil
		})
}

// rotatedKeyDTO is the reply to a rotation: the replacement and its
// one-time secret, shaped like a create, plus when the old key stops.
type rotatedKeyDTO struct {
	Key               apiKeyDTO `json:"key"`
	Secret            string    `json:"secret"`
	PreviousKeyID     string    `json:"previousKeyId"`
	PreviousExpiresAt time.Time `json:"previousExpiresAt"`
}

// --- invocations -----------------------------------------------------------

func (d Deps) invocationRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "invocations-list", Method: http.MethodGet, Path: "/api/v1/tool-calls",
		Summary: "List recent tool calls", Tags: []string{"observability"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			Limit int `query:"limit" default:"50" maximum:"500"`
		}) (*struct {
			Body []invocationDTO `json:"body"`
		}, error) {
			p, err := d.require(ctx, authz.ConnectorsRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			list, err := d.listInvocations(ctx, p.OrgID, in.Limit)
			if err != nil {
				return nil, err
			}
			return &struct {
				Body []invocationDTO `json:"body"`
			}{Body: list}, nil
		})
}

type invocationDTO struct {
	ID         string    `json:"id"`
	ToolName   string    `json:"toolName"`
	Status     string    `json:"status"`
	DurationMS int       `json:"durationMs"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
}

// --- helpers ---------------------------------------------------------------

var sessionSecurity = []map[string][]string{{"session": {}}}

// require resolves the principal and checks a permission.
func (d Deps) require(ctx context.Context, perm authz.Permission, r authz.Resource) (*authz.Principal, error) {
	p, ok := authz.From(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("authentication required")
	}
	if p.OrgID == "" {
		return nil, huma.Error403Forbidden("no organisation selected")
	}
	if err := d.Authz.Require(ctx, perm, r); err != nil {
		d.denied(ctx, perm, r, err.Error())
		return nil, huma.Error403Forbidden(err.Error())
	}
	return p, nil
}

// humaErr maps a service error to an HTTP error. Unmapped errors become
// 500s, whose detail huma hides; the router logs them instead.
func humaErr(err error) error {
	if errors.Is(err, secrets.ErrKeyServiceUnavailable) {
		return newKeyServiceError(err)
	}
	if errors.Is(err, connector.ErrNotFound) || errors.Is(err, mcpserver.ErrNotFound) ||
		errors.Is(err, connector.ErrToolNotFound) || errors.Is(err, mcpauth.ErrKeyNotFound) {
		return huma.Error404NotFound(err.Error())
	}
	if errors.Is(err, mcpauth.ErrRotateRevoked) || errors.Is(err, mcpauth.ErrRotateExpired) || errors.Is(err, mcpauth.ErrRotateTwice) {
		return huma.Error409Conflict(err.Error())
	}
	if errors.Is(err, mcpauth.ErrGraceRange) {
		return huma.Error400BadRequest(err.Error())
	}
	if herr := toolConflict(err); herr != nil {
		return herr
	}
	if herr := memberErr(err); herr != nil {
		return herr
	}
	var invalid *connector.InvalidToolError
	if errors.As(err, &invalid) {
		return huma.Error422UnprocessableEntity(invalid.Error(), toolIssueDetails(invalid.Issues)...)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
		// The constraint and the colliding value stay out of the reply;
		// they name tables and can echo another tenant-visible record.
		return huma.Error409Conflict("this conflicts with a record that already exists")
	}
	if errors.Is(err, connector.ErrNotFromCatalog) || errors.Is(err, connector.ErrNotInCatalog) || errors.Is(err, connector.ErrCatalogNotBehind) {
		return huma.Error409Conflict(err.Error())
	}
	if errors.Is(err, connector.ErrResyncStale) {
		return huma.Error409Conflict(err.Error(), &huma.ErrorDetail{Location: "body", Message: err.Error(), Value: conflictResyncStale})
	}
	if errors.Is(err, connector.ErrMissingCredential) {
		return huma.Error400BadRequest(err.Error())
	}
	status, msg := errStatus(err)
	switch status {
	case http.StatusBadRequest:
		return huma.Error400BadRequest(msg)
	case http.StatusUnauthorized:
		return huma.Error401Unauthorized(msg)
	case http.StatusForbidden:
		return huma.Error403Forbidden(msg)
	case http.StatusTooManyRequests:
		return huma.Error429TooManyRequests(msg)
	case http.StatusOK:
		return nil
	}
	return err
}

// pgUniqueViolation is the SQLSTATE for a unique constraint violation.
const pgUniqueViolation = "23505"

// toolIssueDetails turns the error-severity issues of a definition into
// huma error details located at body.definition.<field>, so a client can
// put each one next to the field it is about. Value carries the rule id,
// not the offending value: the value may hold a credential placeholder
// the client already has, and the rule is what a fix is looked up by.
func toolIssueDetails(issues []adapter.Issue) []error {
	out := make([]error, 0, len(issues))
	for _, i := range issues {
		if i.Severity != adapter.SeverityError {
			continue
		}
		loc := "body.definition"
		if i.Field != "" {
			loc += "." + i.Field
		}
		out = append(out, &huma.ErrorDetail{Message: i.Message, Location: loc, Value: i.Rule})
	}
	return out
}

// listInvocations reads the recent tool calls for an org.
func (d Deps) listInvocations(ctx context.Context, orgID string, limit int) ([]invocationDTO, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	out := []invocationDTO{}
	err := d.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, tool_name, status, duration_ms, COALESCE(error,''), created_at
			FROM tool_invocations WHERE organization_id = $1 ORDER BY created_at DESC LIMIT $2`, orgID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i invocationDTO
			if err := rows.Scan(&i.ID, &i.ToolName, &i.Status, &i.DurationMS, &i.Error, &i.CreatedAt); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}
