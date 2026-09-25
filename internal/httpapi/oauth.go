package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/mcpauth"
)

// oauthRoutes mounts the authorization server. The consent pages are
// server-rendered: an MCP client lands on them mid-flow, so they must work
// without the SPA having loaded.
func (d Deps) oauthRoutes(r chi.Router) {
	r.Get("/.well-known/oauth-authorization-server", d.metadata)
	r.Get("/.well-known/oauth-authorization-server/*", d.metadata)
	r.Get("/.well-known/openid-configuration", d.metadata)
	r.Get("/.well-known/jwks.json", d.jwks)
	r.Get("/.well-known/oauth-protected-resource", d.protectedResource)
	r.Get("/.well-known/oauth-protected-resource/*", d.protectedResource)

	r.Get("/oauth/authorize", d.authorize)
	r.Post("/oauth/consent", d.consent)
	r.Post("/oauth/token", d.token)
	r.Post("/oauth/register", d.register)
	r.Post("/oauth/revoke", d.revoke)
	r.Post("/oauth/introspect", d.introspect)
}

func (d Deps) metadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, d.OAuth.Metadata())
}

func (d Deps) jwks(w http.ResponseWriter, r *http.Request) {
	doc, err := d.OAuth.Keys.JWKS(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "keyring unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(doc)
}

func (d Deps) protectedResource(w http.ResponseWriter, r *http.Request) {
	// /.well-known/oauth-protected-resource/mcp/<id>
	serverID := ""
	if rest := strings.TrimPrefix(chi.URLParam(r, "*"), "mcp/"); rest != "" && rest != chi.URLParam(r, "*") {
		serverID = rest
	}
	writeJSON(w, http.StatusOK, d.OAuth.ProtectedResourceMetadata(serverID))
}

// authorize validates the request, then either shows the consent page or
// sends the user to sign in first.
func (d Deps) authorize(w http.ResponseWriter, r *http.Request) {
	req, err := d.OAuth.BeginAuthorization(r.Context(), r.URL.Query())
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	p, signedIn := authz.From(r.Context())
	if !signedIn || p.AuthMethod != "session" {
		// Come back to this exact request after signing in.
		//nolint:gosec // a fixed local path with an escaped query
		http.Redirect(w, r, "/login?next="+template.URLQueryEscaper("/oauth/authorize?"+r.URL.RawQuery), http.StatusFound)
		return
	}
	// Granting a client a token is handing out a credential, so it needs
	// a recent sign-in like creating an API key does. The consent page is
	// served here rather than by the interface, so the person is sent to
	// the interface's /reauth page and brought back to this request.
	if !fresh(p, d.freshWindow(), time.Now()) {
		//nolint:gosec // a fixed local path with an escaped query
		http.Redirect(w, r, "/reauth?next="+template.URLQueryEscaper("/oauth/authorize?"+r.URL.RawQuery), http.StatusFound)
		return
	}
	servers, _ := d.Servers.List(r.Context(), p.OrgID)
	renderConsent(w, consentData{
		RequestID:  req.ID,
		ClientName: clientLabel(req),
		OrgName:    d.orgName(r, p.OrgID),
		Scopes:     describeScopes(req.Scope),
		Servers:    servers,
		ServerID:   req.ServerID,
		Redirect:   redirectHost(req.RedirectURI),
	})
}

// consent records the decision and redirects back to the client.
func (d Deps) consent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed form")
		return
	}
	p, signedIn := authz.From(r.Context())
	if !signedIn || p.AuthMethod != "session" {
		writeJSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	req, err := d.OAuth.LoadAuthRequest(r.Context(), r.FormValue("request_id"))
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	// The page may have sat open past the window since authorize checked.
	// Declining needs nothing; granting does. The request cannot be
	// rebuilt from the form, so the person starts again from the client,
	// and authorize sends them to confirm who they are first.
	if r.FormValue("decision") == "allow" {
		if err := d.checkFresh(r.Context(), p, "", authz.Resource{OrgID: p.OrgID}); err != nil {
			renderConsent(w, consentData{Error: "Granting access needs a recent sign-in. Go back to " + clientLabel(req) +
				" and connect again; you will be asked to confirm it is you first.", Status: http.StatusForbidden})
			return
		}
	}
	if r.FormValue("decision") != "allow" {
		d.emit(r.Context(), audit.Event{Category: audit.CategoryAuth, Action: "oauth.consent.decline", Outcome: audit.Success,
			TargetKind: "oauth_client", TargetID: req.Client.ClientID, TargetDisplay: req.Client.Name,
			Meta: map[string]any{"scope": req.Scope}})
		//nolint:gosec // the URI was matched against the client's registered list
		http.Redirect(w, r, d.OAuth.Deny(r.Context(), req), http.StatusFound)
		return
	}
	serverID := r.FormValue("server_id")
	if req.ServerID != "" {
		// The client named the server through the resource indicator; the
		// user cannot widen that.
		serverID = req.ServerID
	}
	if serverID == "" {
		renderConsent(w, consentData{Error: "Choose which MCP server this client may use."})
		return
	}
	// The chosen server must belong to the signed-in workspace.
	if _, err := d.Servers.Get(r.Context(), p.OrgID, serverID); err != nil {
		writeJSONError(w, http.StatusForbidden, "that server is not part of this workspace")
		return
	}
	location, err := d.OAuth.Approve(r.Context(), req, mcpauth.Consent{UserID: p.ID, OrgID: p.OrgID, ServerID: serverID,
		SessionID: p.SessionID, AMR: mcpauth.AMR(p.SignIn, p.MFA)})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not complete authorization")
		return
	}
	d.emit(r.Context(), audit.Event{Category: audit.CategoryAuth, Action: "oauth.consent.grant", Outcome: audit.Success,
		TargetKind: "oauth_client", TargetID: req.Client.ClientID, TargetDisplay: req.Client.Name,
		Meta: map[string]any{"scope": req.Scope, "server": serverID}})
	//nolint:gosec // the URI was matched against the client's registered list
	http.Redirect(w, r, location, http.StatusFound)
}

func (d Deps) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, &mcpauth.OAuthError{Code: "invalid_request", Description: "malformed form body", Status: 400})
		return
	}
	clientID, clientSecret := basicClientAuth(r)
	if clientID == "" {
		clientID, clientSecret = r.FormValue("client_id"), r.FormValue("client_secret")
	}
	grant := r.FormValue("grant_type")
	res, err := d.OAuth.Token(r.Context(), r.PostForm, clientID, clientSecret)
	if err != nil {
		d.tokenRefused(r.Context(), grant, clientID, err)
		writeOAuthError(w, err)
		return
	}
	d.tokenIssued(r.Context(), res.Issued)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, res)
}

func (d Deps) register(w http.ResponseWriter, r *http.Request) {
	var in mcpauth.Client
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		writeOAuthError(w, &mcpauth.OAuthError{Code: "invalid_client_metadata", Description: "body must be a JSON object", Status: 400})
		return
	}
	out, err := d.OAuth.Register(r.Context(), in, clientIP(r))
	if err != nil {
		d.emit(r.Context(), audit.Event{Category: audit.CategoryAuth, Action: "oauth.client.register", Outcome: audit.Failure,
			TargetKind: "oauth_client", TargetDisplay: in.Name, Meta: map[string]any{"error": err.Error()}})
		writeOAuthError(w, err)
		return
	}
	d.emit(r.Context(), audit.Event{Category: audit.CategoryAuth, Action: "oauth.client.register", Outcome: audit.Success,
		TargetKind: "oauth_client", TargetID: out.ClientID, TargetDisplay: out.Name,
		Meta: map[string]any{"redirect_uris": out.RedirectURIs, "auth_method": out.AuthMethod, "status": out.Status}})
	writeJSON(w, http.StatusCreated, out)
}

func (d Deps) revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if rv := d.OAuth.Revoke(r.Context(), r.FormValue("token")); rv != nil {
		d.emitAs(r.Context(), audit.Event{OrgID: rv.OrgID, Category: audit.CategoryAuth, Action: "oauth.token.revoke",
			Outcome: audit.Success, ActorKind: "oauth_client", ActorID: rv.ClientID,
			TargetKind: "user", TargetID: rv.UserID, Meta: map[string]any{"family": rv.FamilyID}})
	}
	w.WriteHeader(http.StatusOK)
}

func (d Deps) introspect(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	// Introspection is for resource servers, not the public: require a key.
	if apiKeyFrom(r) == "" {
		writeJSONError(w, http.StatusUnauthorized, "client authentication required")
		return
	}
	caller, err := d.Keys.Authenticate(r.Context(), apiKeyFrom(r), clientIP(r))
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "client authentication failed")
		return
	}
	in := d.OAuth.Introspect(r.Context(), r.FormValue("token"))
	if in.Active && !d.mayIntrospect(r.Context(), caller, in) {
		// RFC 7662 lets the server answer inactive for a token the caller
		// may not know about, which says nothing about whether it exists.
		in = &mcpauth.Introspection{Active: false}
	}
	writeJSON(w, http.StatusOK, in)
}

// mayIntrospect reports whether a key may learn about a token: the token
// is for the key's own workspace, and the key may read the tools of the
// server the token is for, which is what a resource server serving that
// server needs. tools:read is the permission, and a key scoped to MCP use
// passes with mcp:tools:read or mcp:tools:invoke.
func (d Deps) mayIntrospect(ctx context.Context, caller *authz.Principal, in *mcpauth.Introspection) bool {
	if in.Org == "" || in.Org != caller.OrgID {
		return false
	}
	decision, err := d.Authz.Evaluate(ctx, caller, authz.ToolsRead, authz.Resource{OrgID: in.Org, ServerID: in.Server})
	return err == nil && decision.Allow
}

// tokenIssued records a token minted at the token endpoint. The actor is
// whoever the token is for; the client that asked is in the metadata.
func (d Deps) tokenIssued(ctx context.Context, is mcpauth.Issued) {
	kind, id := string(authz.KindUser), is.UserID
	if is.UserID == "" {
		kind, id = string(authz.KindServiceAccount), strings.TrimPrefix(is.Subject, "svc_")
	}
	d.emitAs(ctx, audit.Event{OrgID: is.OrgID, Category: audit.CategoryAuth, Action: "oauth.token",
		Outcome: audit.Success, ActorKind: kind, ActorID: id,
		TargetKind: "oauth_client", TargetID: is.ClientID,
		Meta: map[string]any{"grant": is.Grant, "server": is.ServerID}})
}

// tokenRefused records a refused token request. A malformed request is
// left out: it says nothing about any credential. A replayed refresh
// token is recorded apart, as the leak it is, against the person whose
// tokens were revoked because of it. Other refusals are recorded up to
// a budget per client and minute, and past it counted into one event
// per minute, so a client hammering the endpoint cannot fill the trail.
func (d Deps) tokenRefused(ctx context.Context, grant, clientID string, err error) {
	var oe *mcpauth.OAuthError
	if !asOAuth(err, &oe) || oe.Code == "invalid_request" || oe.Code == "unsupported_grant_type" {
		return
	}
	if u := oe.Reuse; u != nil {
		d.emitAs(ctx, audit.Event{OrgID: u.OrgID, Category: audit.CategoryAuth, Action: "oauth.refresh.reuse",
			Outcome: audit.Denied, ActorKind: "oauth_client", ActorID: u.ClientID,
			TargetKind: "user", TargetID: u.UserID,
			Meta: map[string]any{"family": u.FamilyID, "revoked": "every token in the family"}})
		return
	}
	suppressed, record := d.refusals.admit(clientID)
	if suppressed > 0 {
		d.emitAs(ctx, audit.Event{Category: audit.CategoryAuth, Action: "oauth.token", Outcome: audit.Failure,
			ActorKind: "oauth_client", ActorID: clientID,
			Meta: map[string]any{"suppressed": suppressed, "window": refusalWindow.String(),
				"reason": "further refusals in the previous window were counted, not recorded"}})
	}
	if !record {
		return
	}
	d.emitAs(ctx, audit.Event{Category: audit.CategoryAuth, Action: "oauth.token", Outcome: audit.Failure,
		ActorKind: "oauth_client", ActorID: clientID,
		Meta: map[string]any{"grant": grant, "error": oe.Code, "reason": oe.Description}})
}

// --- helpers ---------------------------------------------------------------

func basicClientAuth(r *http.Request) (string, string) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Basic ") {
		return "", ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Basic "))
	if err != nil {
		return "", ""
	}
	id, secret, _ := strings.Cut(string(raw), ":")
	return id, secret
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOAuthError(w http.ResponseWriter, err error) {
	var oe *mcpauth.OAuthError
	if !asOAuth(err, &oe) {
		writeJSONError(w, http.StatusInternalServerError, "authorization server error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, oe.Status, map[string]string{"error": oe.Code, "error_description": oe.Description})
}

func asOAuth(err error, target **mcpauth.OAuthError) bool {
	return errors.As(err, target)
}

func (d Deps) orgName(r *http.Request, orgID string) string {
	p, _ := authz.From(r.Context())
	if p == nil {
		return ""
	}
	orgs, err := d.Identity.Orgs(r.Context(), p.ID)
	if err != nil {
		return ""
	}
	for _, o := range orgs {
		if o.ID == orgID {
			return o.Name
		}
	}
	return ""
}

func clientLabel(req *mcpauth.AuthRequest) string {
	if req.Client.Name != "" {
		return req.Client.Name
	}
	return req.Client.ClientID
}

func redirectHost(uri string) string {
	if i := strings.Index(uri, "://"); i >= 0 {
		rest := uri[i+3:]
		if j := strings.IndexAny(rest, "/?"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return uri
}

// describeScopes turns scope strings into what they actually permit.
func describeScopes(scope string) []string {
	out := []string{}
	fields := strings.Fields(scope)
	if len(fields) == 0 {
		fields = []string{authz.ScopeToolsRead, authz.ScopeToolsInvoke}
	}
	for _, s := range fields {
		switch s {
		case authz.ScopeToolsRead:
			out = append(out, "See which tools this server offers")
		case authz.ScopeToolsInvoke:
			out = append(out, "Call those tools on your behalf")
		case mcpauth.ScopeOfflineAccess:
			out = append(out, "Stay connected without asking you again")
		}
	}
	return out
}
