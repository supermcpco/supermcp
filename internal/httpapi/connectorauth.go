package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/httpclient"
	"github.com/supermcpco/supermcp/internal/ssrf"
	"github.com/supermcpco/supermcp/internal/upstreamauth"
)

// The upstream consent flow: the one grant a connector cannot complete on
// its own, because it needs a person at the vendor to approve access.
//
// Two routes. An administrator asks to connect a connector and gets the
// vendor's authorization URL to open; the vendor sends the browser back to
// one callback, shared by every connector, which turns the code into a
// refresh token and leaves it where the refresh grant looks.

// callbackDeadline bounds the token exchange and the two writes that
// follow it. The administrator is sitting in front of a blank tab.
const callbackDeadline = 30 * time.Second

// refreshCredential is the credential an adapter's refresh token lands in
// when the adapter declares no placeholder of its own. The refresh grant
// reads the token through the auth block and nowhere else, so a connector
// whose auth block points at nothing could complete the consent flow and
// still be unusable.
const refreshCredential = "OAUTH_REFRESH_TOKEN" //nolint:gosec // a credential's name, not its value

// consentFlow builds the flow. It is called once per route group at
// start-up, never per request.
//
// The client is built here rather than passed down from build.go because
// this is the only thing in the router that dials outwards, and the SSRF
// policy it needs is the one the process already reads from the
// environment. The token endpoint comes from an adapter, so it goes
// through the guard like every other adapter-supplied URL.
func (d Deps) consentFlow() *upstreamauth.AuthCode {
	policy := ssrf.FromEnv(os.Getenv)
	if d.Config != nil && d.Config.Dev {
		policy.AllowLoopback = true
	}
	client := httpclient.New(ssrf.NewDialer(policy), "connector-consent", httpclient.DefaultPolicy())
	var public *url.URL
	if d.Config != nil {
		public = d.Config.PublicURL
	}
	return upstreamauth.NewAuthCode(upstreamauth.NewDBConsentStore(d.DB), client, public)
}

// connectorAuthBrowserRoutes is the vendor's way back. It is not part of
// the JSON API: a browser follows it, and what it answers with is a
// redirect to a page.
func (d Deps) connectorAuthBrowserRoutes(r chi.Router) {
	flow := d.consentFlow()
	r.Get("/auth/connectors/callback", func(w http.ResponseWriter, req *http.Request) {
		d.connectorAuthCallback(flow, w, req)
	})
}

type connectorAuthStart struct {
	AuthorizationURL string   `json:"authorizationUrl"`
	RedirectURI      string   `json:"redirectUri"`
	Scopes           []string `json:"scopes"`
}

func (d Deps) connectorAuthRoutes(api huma.API) {
	flow := d.consentFlow()

	// The redirect URI is registered with the vendor once, before any of
	// this can run, so it has to be readable without starting a flow.
	huma.Register(api, huma.Operation{OperationID: "connectors-oauth-redirect-uri", Method: http.MethodGet,
		Path: "/api/v1/connectors/oauth/redirect-uri", Summary: "The redirect URI to register with an OAuth2 vendor",
		Tags: []string{"connectors"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct {
			Body struct {
				RedirectURI string `json:"redirectUri"`
			}
		}, error) {
			if _, err := d.require(ctx, authz.ConnectorsRead, authz.Resource{}); err != nil {
				return nil, err
			}
			out := &struct {
				Body struct {
					RedirectURI string `json:"redirectUri"`
				}
			}{}
			out.Body.RedirectURI = flow.RedirectURI()
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "connectors-oauth-authorize", Method: http.MethodPost,
		Path:    "/api/v1/connectors/{id}/oauth/authorize",
		Summary: "Start the OAuth2 consent flow for a connector", Tags: []string{"connectors"},
		Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct{ Body connectorAuthStart }, error) {
			p, err := d.require(ctx, authz.ConnectorsAuth, authz.Resource{ConnectorID: in.ID})
			if err != nil {
				return nil, err
			}
			res, err := d.Connectors.Resolve(ctx, p.OrgID, in.ID)
			if err != nil {
				d.adminFailed(ctx, "connector.oauth.authorize", "connector", in.ID, err)
				return nil, humaErr(err)
			}
			params, err := upstreamauth.ParamsFor(res.Connector, p.OrgID, res.Env)
			if err != nil {
				d.adminFailed(ctx, "connector.oauth.authorize", "connector", in.ID, err)
				return nil, huma.Error400BadRequest(err.Error())
			}
			authURL, err := flow.Begin(ctx, params, p.ID)
			if err != nil {
				d.adminFailed(ctx, "connector.oauth.authorize", "connector", in.ID, err)
				return nil, humaErr(err)
			}
			// What was asked for is recorded before anyone approves it, so
			// a consent screen nobody remembers agreeing to has a trail.
			d.emit(ctx, audit.Event{Category: audit.CategorySecrets, Action: "connector.oauth.authorize",
				Outcome: audit.Success, TargetKind: "connector", TargetID: in.ID,
				Meta: map[string]any{"scopes": params.Scopes, "authorization_host": hostOf(params.AuthorizationURL)}})
			return &struct{ Body connectorAuthStart }{Body: connectorAuthStart{
				AuthorizationURL: authURL, RedirectURI: flow.RedirectURI(), Scopes: params.Scopes,
			}}, nil
		})
}

// connectorAuthCallback finishes the flow the administrator started.
func (d Deps) connectorAuthCallback(flow *upstreamauth.AuthCode, w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), callbackDeadline)
	defer cancel()
	q := r.URL.Query()

	// The state is spent first, before anything else in the request is
	// believed — including the vendor saying it went wrong. Otherwise an
	// error parameter is a way to ask repeatedly whether a state exists.
	consent, err := flow.Consume(ctx, q.Get("state"))
	if err != nil {
		d.connectorAuthFailed(ctx, w, r, "", "", err)
		return
	}
	if e := q.Get("error"); e != "" {
		// Only that the vendor refused, never its words: the description
		// is free text from somewhere else and may name an internal host.
		d.connectorAuthFailed(ctx, w, r, consent.OrgID, consent.ConnectorID, upstreamauth.ErrVendorRejected)
		return
	}
	// The consent says which connector this is. Nothing else in the
	// request gets a say, and the organisation comes with it, because the
	// vendor's redirect carries no session.
	res, err := d.Connectors.Resolve(ctx, consent.OrgID, consent.ConnectorID)
	if err != nil {
		d.connectorAuthFailed(ctx, w, r, consent.OrgID, consent.ConnectorID, err)
		return
	}
	params, err := upstreamauth.ParamsFor(res.Connector, consent.OrgID, res.Env)
	if err != nil {
		d.connectorAuthFailed(ctx, w, r, consent.OrgID, consent.ConnectorID, err)
		return
	}
	tok, err := flow.Exchange(ctx, params, consent, q.Get("code"))
	if err != nil {
		d.connectorAuthFailed(ctx, w, r, consent.OrgID, consent.ConnectorID, err)
		return
	}
	if err := d.storeConnectorGrant(ctx, consent.OrgID, consent.ConnectorID, tok); err != nil {
		d.connectorAuthFailed(ctx, w, r, consent.OrgID, consent.ConnectorID, err)
		return
	}
	d.emit(ctx, audit.Event{OrgID: consent.OrgID, Category: audit.CategorySecrets, Action: "connector.oauth.connect",
		Outcome: audit.Success, TargetKind: "connector", TargetID: consent.ConnectorID,
		Meta: map[string]any{"scopes": params.Scopes, "started_by": consent.ActorID}})
	//nolint:gosec // the destination is built below from a connector id, not from the request
	http.Redirect(w, r, connectorPage(consent.ConnectorID, "connected", "1"), http.StatusFound)
}

// storeConnectorGrant puts what the vendor issued where the rest of the
// system already looks for it: the refresh token sealed among the
// connector's credentials, so the refresh grant renews from it, and the
// access token in the connector's token store, so the first tool call
// after connecting does not have to spend the refresh token to get one.
func (d Deps) storeConnectorGrant(ctx context.Context, orgID, connectorID string, tok *upstreamauth.Token) error {
	c, err := d.Connectors.Get(ctx, orgID, connectorID)
	if err != nil {
		return err
	}
	name := envPlaceholder(c.Auth.RefreshToken)
	if name == "" {
		// An adapter that declares no refreshToken placeholder gets one.
		// The auth block holds the reference and the sealed credential
		// holds the value, which is the invariant everywhere else.
		auth := c.Auth
		auth.RefreshToken = "{{env." + refreshCredential + "}}"
		if _, err := d.Connectors.Update(ctx, orgID, connectorID, connector.UpdateInput{Auth: &auth}); err != nil {
			return err
		}
		name = refreshCredential
	}
	if err := d.Connectors.SetCredentials(ctx, orgID, connectorID, map[string]string{name: tok.Refresh}); err != nil {
		return err
	}
	store := &connector.TokenStore{S: d.Connectors, OrgID: orgID}
	return store.Put(ctx, connectorID, tok)
}

// connectorAuthFailed sends the administrator back to the connector with
// something they can act on, and keeps the detail in the log and the
// audit trail. The vendor's own message never reaches the URL: it is free
// text from elsewhere, and it has been known to name an internal address.
func (d Deps) connectorAuthFailed(ctx context.Context, w http.ResponseWriter, r *http.Request, orgID, connectorID string, err error) {
	d.Log.Warn("connector consent failed", "err", err, "connector", connectorID, "path", r.URL.Path)
	d.emit(ctx, audit.Event{OrgID: orgID, Category: audit.CategorySecrets, Action: "connector.oauth.connect",
		Outcome: audit.Failure, TargetKind: "connector", TargetID: connectorID,
		Meta: map[string]any{"reason": err.Error()}})
	reason := "connect_failed"
	switch {
	case errors.Is(err, upstreamauth.ErrConsentInvalid):
		reason = "expired"
	case errors.Is(err, upstreamauth.ErrNoRefreshToken):
		reason = "no_refresh_token"
	case errors.Is(err, upstreamauth.ErrVendorRejected):
		reason = "vendor_refused"
	case errors.Is(err, upstreamauth.ErrNotAuthCode):
		reason = "not_supported"
	case errors.Is(err, connector.ErrNotFound):
		reason = "unavailable"
	}
	//nolint:gosec // a local path with a fixed set of reasons
	http.Redirect(w, r, connectorPage(connectorID, "connect_error", reason), http.StatusFound)
}

// connectorPage is where an administrator resumes. The path is built
// here and never taken from the request, so there is nothing to point
// somewhere else.
func connectorPage(connectorID, key, value string) string {
	q := url.Values{key: {value}}
	if connectorID != "" {
		q.Set("connector", connectorID)
	}
	return "/connectors?" + q.Encode()
}

// envPlaceholder returns the credential name a "{{env.NAME}}" string
// refers to, or "" for anything else.
func envPlaceholder(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{{env.") || !strings.HasSuffix(s, "}}") {
		return ""
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "{{env."), "}}"))
}

// hostOf names the vendor an event is about without repeating the query
// string, which carries the state.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}
