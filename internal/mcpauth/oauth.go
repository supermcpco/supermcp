package mcpauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// Token lifetimes.
const (
	AccessTokenTTL  = time.Hour
	RefreshTokenTTL = 30 * 24 * time.Hour
	CodeTTL         = 5 * time.Minute
	AuthSessionTTL  = 15 * time.Minute
)

// Scopes an MCP client may ask for.
const (
	ScopeOfflineAccess = "offline_access"
)

// OAuth errors, reported with the RFC 6749 code the client expects.
type OAuthError struct {
	Code        string // invalid_request, invalid_client, invalid_grant, ...
	Description string
	Status      int
	// Reuse is set when a spent refresh token came back and its family was
	// revoked. It never reaches the client; it is what the audit trail
	// records, because a reused refresh token means one leaked.
	Reuse *Reuse
}

// Reuse identifies the token family a replayed refresh token burned.
type Reuse struct {
	OrgID    string
	UserID   string
	ClientID string
	FamilyID string
}

func (e *OAuthError) Error() string { return e.Code + ": " + e.Description }

func oauthErr(code, description string, status int) *OAuthError {
	return &OAuthError{Code: code, Description: description, Status: status}
}

// DCRMode controls who may register a client.
type DCRMode string

const (
	// DCROpen accepts any registration (development only).
	DCROpen DCRMode = "open"
	// DCRApproval registers clients as pending until an admin approves.
	DCRApproval DCRMode = "approval"
	// DCRClosed refuses registration; clients must be pre-registered.
	DCRClosed DCRMode = "closed"
)

// OAuth is the authorization server for MCP clients.
type OAuth struct {
	DB      *tenant.DB
	Keys    *Keyring
	NewID   func() string
	Issuer  string
	Mode    DCRMode
	now     func() time.Time
	Clients ClientLimiter
	// Accounts authenticates the non-human principals that use the client
	// credentials grant. Nil leaves that grant unsupported.
	Accounts ServiceAccounts
	// Sessions reports whether the browser session a token was issued
	// through has ended. Nil refuses every token that names a session.
	Sessions Sessions
}

// Sessions tells whether a browser session was ended: signed out, ended by
// its owner or an administrator, replaced, or its person deactivated. A
// session that merely expired is not ended; the refresh tokens it
// consented to outlive it, which is what offline access is for.
type Sessions interface {
	// SessionEnded takes the session's public id, the sid claim, and
	// reports true for a session that is not on record.
	SessionEnded(ctx context.Context, publicID string) (bool, error)
}

// ServiceAccounts verifies client credentials that belong to a service
// account rather than to a person's client, and reports whether a token it
// was issued still counts.
type ServiceAccounts interface {
	AuthenticateServiceAccount(ctx context.Context, clientID, secret string) (*authz.Principal, []string, error)
	// ServiceAccountTokenEpoch returns the epoch a token must carry and
	// whether the account is enabled. Disabling an account moves its
	// epoch on, which refuses every token issued before.
	ServiceAccountTokenEpoch(ctx context.Context, orgID, id string) (epoch int, active bool, err error)
}

// claimEpoch carries a service account's token epoch in its access token.
const claimEpoch = "sa_epoch"

// Claims naming the browser session behind a token and how it signed in.
const (
	claimSID = "sid"
	claimAMR = "amr"
)

// AMR returns the RFC 8176 authentication method references for a browser
// session. A password session says "pwd". A single sign-on session
// repeats the registered values its provider reported, in the provider's
// order, except "mfa". "mfa" is added when mfa is true: the session has a
// second factor on record, which for single sign-on means the provider's
// answer met the rule configured for it (an OpenID Connect ID token) or
// named one (a SAML assertion). A provider that reports "mfa" without
// meeting that rule does not get it repeated. The result is nil when
// nothing is known.
func AMR(signIn authz.SignIn, mfa bool) []string {
	var out []string
	if signIn.Method == "password" {
		out = append(out, "pwd")
	}
	for _, m := range signIn.Methods {
		if m != "mfa" && registeredAMR[m] && !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	if mfa {
		out = append(out, "mfa")
	}
	return out
}

// registeredAMR are the values in the IANA registry RFC 8176 set up. A
// provider's own values (Entra's "rsa" or "ngcmfa", say) mean nothing to
// a client reading our tokens, so they are not repeated.
var registeredAMR = map[string]bool{
	"face": true, "fpt": true, "geo": true, "hwk": true, "iris": true, "kba": true, "mca": true,
	"mfa": true, "otp": true, "pin": true, "pop": true, "pwd": true, "rba": true, "retina": true,
	"sc": true, "sms": true, "swk": true, "tel": true, "user": true, "vbm": true, "wia": true,
}

// ClientLimiter rate limits dynamic registration.
type ClientLimiter interface {
	Allow(key string) bool
}

// NewOAuth builds the authorization server.
func NewOAuth(db *tenant.DB, keys *Keyring, issuer string, mode DCRMode, newID func() string) *OAuth {
	if mode == "" {
		mode = DCRApproval
	}
	return &OAuth{DB: db, Keys: keys, NewID: newID, Issuer: strings.TrimRight(issuer, "/"), Mode: mode, now: time.Now}
}

// --- client registration ---------------------------------------------------

// Client is a registered OAuth client.
type Client struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Name         string   `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types,omitempty"`
	AuthMethod   string   `json:"token_endpoint_auth_method,omitempty"`
	Scope        string   `json:"scope,omitempty"`
	Status       string   `json:"-"`
}

// Register implements RFC 7591 dynamic client registration.
func (o *OAuth) Register(ctx context.Context, in Client, ip string) (*Client, error) {
	if o.Mode == DCRClosed {
		return nil, oauthErr("access_denied", "dynamic client registration is disabled on this instance", 403)
	}
	if o.Clients != nil && !o.Clients.Allow(ip) {
		return nil, oauthErr("temporarily_unavailable", "too many registrations from this address", 429)
	}
	if len(in.RedirectURIs) == 0 {
		return nil, oauthErr("invalid_redirect_uri", "at least one redirect_uri is required", 400)
	}
	for _, u := range in.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return nil, oauthErr("invalid_redirect_uri", err.Error(), 400)
		}
	}
	grants := in.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code", "refresh_token"}
	}
	for _, g := range grants {
		switch g {
		case "authorization_code", "refresh_token":
		default:
			return nil, oauthErr("invalid_client_metadata", "unsupported grant type "+g, 400)
		}
	}
	status := "approved"
	if o.Mode == DCRApproval {
		status = "pending"
	}
	out := &Client{ClientID: "smc_" + randomString(24), Name: in.Name, RedirectURIs: in.RedirectURIs,
		GrantTypes: grants, AuthMethod: "none", Scope: in.Scope, Status: status}
	// Public clients (native and browser apps) use PKCE without a secret;
	// a confidential client asks for one explicitly.
	var secretHash *string
	if in.AuthMethod == "client_secret_basic" || in.AuthMethod == "client_secret_post" {
		out.AuthMethod = in.AuthMethod
		out.ClientSecret = randomString(32)
		h := sha256.Sum256([]byte(out.ClientSecret))
		s := base64.RawURLEncoding.EncodeToString(h[:])
		secretHash = &s
	}
	err := o.DB.Bypass(ctx, "oauth-register", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO oauth_clients (id, client_id, client_secret_hash, client_name, redirect_uris, grant_types, token_endpoint_auth_method, scope, status, registration_ip)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			o.NewID(), out.ClientID, secretHash, out.Name, out.RedirectURIs, out.GrantTypes, out.AuthMethod, out.Scope, status, nullableIP(ip))
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func nullableIP(ip string) any {
	if ip == "" {
		return nil
	}
	return ip
}

// validateRedirectURI enforces exact-match URIs: https anywhere, http only
// on loopback (RFC 8252), and never a wildcard or a fragment.
func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri %q is not a URL", raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "*") {
		return fmt.Errorf("redirect_uri %q must not contain a fragment or wildcard", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("redirect_uri %q may use http only on 127.0.0.1 or [::1]", raw)
	case "":
		return fmt.Errorf("redirect_uri %q needs a scheme", raw)
	default:
		// A private-use scheme (com.example.app:/callback) is how native
		// apps receive the code.
		if strings.Contains(u.Scheme, ".") {
			return nil
		}
		return fmt.Errorf("redirect_uri scheme %q is not allowed", u.Scheme)
	}
}

// LoadClient reads a client by its client_id.
func (o *OAuth) LoadClient(ctx context.Context, clientID string) (*Client, string, error) {
	var c Client
	var secretHash *string
	err := o.DB.Bypass(ctx, "oauth-client", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT client_id, client_name, redirect_uris, grant_types, token_endpoint_auth_method, scope, status, client_secret_hash
			FROM oauth_clients WHERE client_id = $1`, clientID).
			Scan(&c.ClientID, &c.Name, &c.RedirectURIs, &c.GrantTypes, &c.AuthMethod, &c.Scope, &c.Status, &secretHash)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", oauthErr("invalid_client", "unknown client", 401)
	}
	if err != nil {
		return nil, "", err
	}
	h := ""
	if secretHash != nil {
		h = *secretHash
	}
	return &c, h, nil
}

// --- authorization ---------------------------------------------------------

// AuthRequest is a validated /authorize request awaiting consent.
type AuthRequest struct {
	ID                  string
	Client              *Client
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Resource            string
	ServerID            string
}

// BeginAuthorization validates an authorization request and stores it for
// the consent step. PKCE with S256 is mandatory: without it an intercepted
// code can be redeemed by anyone.
func (o *OAuth) BeginAuthorization(ctx context.Context, q url.Values) (*AuthRequest, error) {
	clientID := q.Get("client_id")
	if clientID == "" {
		return nil, oauthErr("invalid_request", "client_id is required", 400)
	}
	client, _, err := o.LoadClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client.Status != "approved" {
		return nil, oauthErr("unauthorized_client", "this client is awaiting approval by an administrator", 403)
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" && len(client.RedirectURIs) == 1 {
		redirect = client.RedirectURIs[0]
	}
	if !containsString(client.RedirectURIs, redirect) {
		// Never redirect to an unregistered URI: that is an open redirector.
		return nil, oauthErr("invalid_request", "redirect_uri does not match a registered URI", 400)
	}
	if rt := q.Get("response_type"); rt != "code" {
		return nil, oauthErr("unsupported_response_type", "only the authorization code flow is supported", 400)
	}
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	if challenge == "" {
		return nil, oauthErr("invalid_request", "code_challenge is required (PKCE)", 400)
	}
	if method != "S256" {
		return nil, oauthErr("invalid_request", "code_challenge_method must be S256", 400)
	}
	req := &AuthRequest{ID: randomString(24), Client: client, RedirectURI: redirect, State: q.Get("state"),
		CodeChallenge: challenge, CodeChallengeMethod: method, Scope: q.Get("scope"), Resource: q.Get("resource")}
	req.ServerID = serverFromResource(req.Resource, o.Issuer)
	err = o.DB.Bypass(ctx, "oauth-authorize", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO oauth_sessions (id, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope, resource, expires_at)
			VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,$7,NULLIF($8,''),$9)`,
			req.ID, clientID, redirect, req.State, challenge, method, req.Scope, req.Resource, o.now().Add(AuthSessionTTL))
		return err
	})
	if err != nil {
		return nil, err
	}
	return req, nil
}

// LoadAuthRequest reads a pending authorization request.
func (o *OAuth) LoadAuthRequest(ctx context.Context, id string) (*AuthRequest, error) {
	var req AuthRequest
	var clientID string
	var state, resource *string
	err := o.DB.Bypass(ctx, "oauth-session", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope, resource
			FROM oauth_sessions WHERE id = $1 AND expires_at > now()`, id).
			Scan(&req.ID, &clientID, &req.RedirectURI, &state, &req.CodeChallenge, &req.CodeChallengeMethod, &req.Scope, &resource)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oauthErr("invalid_request", "this authorization request has expired; start again from your client", 400)
	}
	if err != nil {
		return nil, err
	}
	if state != nil {
		req.State = *state
	}
	if resource != nil {
		req.Resource = *resource
	}
	req.ServerID = serverFromResource(req.Resource, o.Issuer)
	client, _, err := o.LoadClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	req.Client = client
	return &req, nil
}

// Consent is who granted an authorization request, from which browser
// session, and for which server.
type Consent struct {
	UserID   string
	OrgID    string
	ServerID string
	// SessionID is the browser session that consented. It becomes the
	// sid claim, and ending the session ends the tokens.
	SessionID string
	// AMR is how that session authenticated (see AMR).
	AMR []string
}

// Approve turns a consented request into a redirect carrying the code.
func (o *OAuth) Approve(ctx context.Context, req *AuthRequest, c Consent) (string, error) {
	code := randomString(32)
	amr := c.AMR
	if amr == nil {
		amr = []string{}
	}
	err := o.DB.Bypass(ctx, "oauth-approve", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO oauth_codes (code, client_id, user_id, organization_id, server_id, redirect_uri, code_challenge, code_challenge_method, scope, resource, expires_at, session_id, amr)
			VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8,$9,NULLIF($10,''),$11,NULLIF($12,''),$13)`,
			code, req.Client.ClientID, c.UserID, c.OrgID, c.ServerID, req.RedirectURI, req.CodeChallenge, req.CodeChallengeMethod, req.Scope, req.Resource, o.now().Add(CodeTTL),
			c.SessionID, amr); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM oauth_sessions WHERE id = $1`, req.ID)
		return err
	})
	if err != nil {
		return "", err
	}
	return redirectWith(req.RedirectURI, map[string]string{"code": code, "state": req.State, "iss": o.Issuer}), nil
}

// Deny builds the redirect for a refused consent.
func (o *OAuth) Deny(ctx context.Context, req *AuthRequest) string {
	_ = o.DB.Bypass(ctx, "oauth-deny", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM oauth_sessions WHERE id = $1`, req.ID)
		return err
	})
	return redirectWith(req.RedirectURI, map[string]string{
		"error": "access_denied", "error_description": "the user declined the request", "state": req.State, "iss": o.Issuer,
	})
}

func redirectWith(base string, params map[string]string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// serverFromResource maps an RFC 8707 resource indicator to a server id,
// so a token is bound to the one server the client asked for.
func serverFromResource(resource, issuer string) string {
	if resource == "" {
		return ""
	}
	u, err := url.Parse(resource)
	if err != nil {
		return ""
	}
	path := strings.TrimPrefix(u.Path, "/")
	if rest, ok := strings.CutPrefix(path, "mcp/"); ok {
		return rest
	}
	return ""
}

// --- token endpoint --------------------------------------------------------

// TokenResponse is the RFC 6749 success body.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	// Issued says who the token was for, for the audit trail. It is not
	// part of the response.
	Issued Issued `json:"-"`
}

// Issued describes a token that was just minted.
type Issued struct {
	Grant    string
	OrgID    string
	UserID   string // "" for a service account
	Subject  string // user_<id> or svc_<id>
	ClientID string
	ServerID string
}

// Token handles authorization_code and refresh_token grants.
func (o *OAuth) Token(ctx context.Context, form url.Values, clientID, clientSecret string) (*TokenResponse, error) {
	if clientID == "" {
		clientID = form.Get("client_id")
	}
	if clientID == "" {
		return nil, oauthErr("invalid_client", "client_id is required", 401)
	}
	// A service account authenticates as itself, not as a registered
	// client, so it is resolved before the client lookup that would fail.
	if form.Get("grant_type") == "client_credentials" {
		out, err := o.clientCredentials(ctx, form, clientID, clientSecret)
		if out != nil {
			out.Issued.Grant = "client_credentials"
		}
		return out, err
	}
	client, secretHash, err := o.LoadClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	// Authorize already refuses a client that is not approved; this stops
	// one that was rejected after it had tokens from refreshing them.
	if client.Status != "approved" {
		return nil, oauthErr("unauthorized_client", "this client is not approved on this instance", 400)
	}
	if client.AuthMethod != "none" {
		h := sha256.Sum256([]byte(clientSecret))
		want := base64.RawURLEncoding.EncodeToString(h[:])
		if secretHash == "" || subtle.ConstantTimeCompare([]byte(want), []byte(secretHash)) != 1 {
			return nil, oauthErr("invalid_client", "client authentication failed", 401)
		}
	}
	var out *TokenResponse
	switch form.Get("grant_type") {
	case "authorization_code":
		out, err = o.exchangeCode(ctx, client, form)
	case "refresh_token":
		out, err = o.refresh(ctx, client, form)
	default:
		return nil, oauthErr("unsupported_grant_type",
			"this server supports authorization_code, refresh_token and client_credentials", 400)
	}
	if out != nil {
		out.Issued.Grant = form.Get("grant_type")
	}
	return out, err
}

// clientCredentials issues a token to a service account. There is no user
// and no refresh token: the account re-authenticates with its secret,
// which it holds anyway.
func (o *OAuth) clientCredentials(ctx context.Context, form url.Values, clientID, clientSecret string) (*TokenResponse, error) {
	if o.Accounts == nil {
		return nil, oauthErr("unsupported_grant_type", "this server does not issue tokens to service accounts", 400)
	}
	if clientSecret == "" {
		return nil, oauthErr("invalid_client", "a client secret is required", 401)
	}
	p, allowed, err := o.Accounts.AuthenticateServiceAccount(ctx, clientID, clientSecret)
	if err != nil {
		return nil, oauthErr("invalid_client", "client authentication failed", 401)
	}
	// The resource indicator names the server the token is for; an account
	// bound to one server may not ask for another.
	serverID := serverFromResource(form.Get("resource"), o.Issuer)
	if r := form.Get("resource"); r != "" && serverID == "" {
		return nil, oauthErr("invalid_target", "the resource indicator does not name an MCP server on this instance", 400)
	}
	if p.ServerID != "" {
		if serverID != "" && serverID != p.ServerID {
			return nil, oauthErr("invalid_target", "this service account is bound to a different MCP server", 400)
		}
		serverID = p.ServerID
	}
	// Narrow the request to what the account is allowed to hold.
	granted := allowed
	if want := scopeList(form.Get("scope")); len(want) > 0 {
		granted = nil
		for _, s := range want {
			if containsString(allowed, s) {
				granted = append(granted, s)
			}
		}
		if len(granted) == 0 {
			return nil, oauthErr("invalid_scope", "none of the requested scopes are granted to this service account", 400)
		}
	}
	epoch, active, err := o.Accounts.ServiceAccountTokenEpoch(ctx, p.OrgID, p.ID)
	if err != nil {
		return nil, fmt.Errorf("read service account epoch: %w", err)
	}
	if !active {
		// Disabled between the secret check and here.
		return nil, oauthErr("invalid_client", "client authentication failed", 401)
	}
	return o.issueToken(ctx, grant{subject: "svc_" + p.ID, clientID: clientID, orgID: p.OrgID, serverID: serverID,
		scope: strings.Join(granted, " "), extra: map[string]any{claimEpoch: epoch}})
}

func (o *OAuth) exchangeCode(ctx context.Context, client *Client, form url.Values) (*TokenResponse, error) {
	code := form.Get("code")
	verifier := form.Get("code_verifier")
	if code == "" || verifier == "" {
		return nil, oauthErr("invalid_request", "code and code_verifier are required", 400)
	}
	var userID, orgID, redirect, challenge, scope, codeClient string
	var serverID, sessionID, publicSID *string
	var amr []string
	var consumed *time.Time
	var expires time.Time
	// Read under a row lock, then consume in the same transaction: two
	// concurrent redemptions cannot both succeed.
	err := o.DB.Bypass(ctx, "oauth-code", func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT c.client_id, c.user_id, c.organization_id, c.server_id, c.redirect_uri, c.code_challenge,
				c.scope, c.expires_at, c.consumed_at, c.session_id, c.amr, s.public_id
			FROM oauth_codes c LEFT JOIN sessions s ON s.id = c.session_id
			WHERE c.code = $1 FOR UPDATE OF c`, code).
			Scan(&codeClient, &userID, &orgID, &serverID, &redirect, &challenge, &scope, &expires, &consumed,
				&sessionID, &amr, &publicSID); err != nil {
			return err
		}
		if consumed != nil || expires.Before(o.now()) {
			return nil
		}
		_, err := tx.Exec(ctx, `UPDATE oauth_codes SET consumed_at = now() WHERE code = $1`, code)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oauthErr("invalid_grant", "the authorization code is invalid", 400)
	}
	if err != nil {
		return nil, err
	}
	if consumed != nil {
		return nil, oauthErr("invalid_grant", "this authorization code was already used", 400)
	}
	if expires.Before(o.now()) {
		return nil, oauthErr("invalid_grant", "the authorization code has expired", 400)
	}
	if codeClient != client.ClientID {
		return nil, oauthErr("invalid_grant", "this code was issued to another client", 400)
	}
	if r := form.Get("redirect_uri"); r != "" && r != redirect {
		return nil, oauthErr("invalid_grant", "redirect_uri does not match the authorization request", 400)
	}
	sum := sha256.Sum256([]byte(verifier))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) != 1 {
		// The code is spent either way: a failed verifier means whoever
		// presented it is not the client that started the flow.
		return nil, oauthErr("invalid_grant", "PKCE verification failed", 400)
	}
	return o.issueToken(ctx, grant{subject: "user_" + userID, clientID: client.ClientID, userID: userID, orgID: orgID,
		serverID: deref(serverID), scope: scope, sessionID: deref(sessionID), publicSID: deref(publicSID), amr: amr})
}

func (o *OAuth) refresh(ctx context.Context, client *Client, form url.Values) (*TokenResponse, error) {
	presented := form.Get("refresh_token")
	if presented == "" {
		return nil, oauthErr("invalid_request", "refresh_token is required", 400)
	}
	// A rotation that lost a race (the token was consumed, revoked or
	// moved to a replacing session meanwhile) is read again once: the
	// second read sees what happened and answers for it.
	out, err := o.refreshOnce(ctx, client, presented)
	if errors.Is(err, errRotationRaced) {
		out, err = o.refreshOnce(ctx, client, presented)
	}
	if errors.Is(err, errRotationRaced) {
		return nil, oauthErr("invalid_grant", "the refresh token is expired or revoked", 400)
	}
	return out, err
}

func (o *OAuth) refreshOnce(ctx context.Context, client *Client, presented string) (*TokenResponse, error) {
	hash := sha256.Sum256([]byte(presented))
	var id, familyID, userID, orgID, scope string
	var serverID, sessionID, publicSID *string
	var amr []string
	var consumed, revoked *time.Time
	var expires time.Time
	err := o.DB.Bypass(ctx, "oauth-refresh", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT t.id, t.family_id, t.user_id, t.organization_id, t.server_id, t.scope, t.expires_at,
				t.consumed_at, t.revoked_at, t.session_id, t.amr, s.public_id
			FROM oauth_refresh_tokens t LEFT JOIN sessions s ON s.id = t.session_id
			WHERE t.token_hash = $1 AND t.client_id = $2`, hash[:], client.ClientID).
			Scan(&id, &familyID, &userID, &orgID, &serverID, &scope, &expires, &consumed, &revoked, &sessionID, &amr, &publicSID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oauthErr("invalid_grant", "unknown refresh token", 400)
	}
	if err != nil {
		return nil, err
	}
	if consumed != nil {
		// A rotated token presented twice means it leaked: burn the family.
		o.revokeFamily(ctx, familyID)
		e := oauthErr("invalid_grant", "this refresh token was already used; all tokens in the family were revoked", 400)
		e.Reuse = &Reuse{OrgID: orgID, UserID: userID, ClientID: client.ClientID, FamilyID: familyID}
		return nil, e
	}
	if revoked != nil || expires.Before(o.now()) {
		return nil, oauthErr("invalid_grant", "the refresh token is expired or revoked", 400)
	}
	return o.issueToken(ctx, grant{subject: "user_" + userID, clientID: client.ClientID, userID: userID, orgID: orgID,
		serverID: deref(serverID), scope: scope, familyID: familyID, consumeID: id,
		sessionID: deref(sessionID), publicSID: deref(publicSID), amr: amr})
}

// revokeFamily ends every token in a refresh token family. It is best
// effort: the caller is refusing the request either way.
func (o *OAuth) revokeFamily(ctx context.Context, familyID string) {
	_ = o.DB.Bypass(ctx, "oauth-refresh-family", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL`, familyID)
		return err
	})
}

// grant is what a token is minted for.
type grant struct {
	subject  string // user_<id> or svc_<id>
	clientID string
	userID   string // "" for a service account, which gets no refresh token
	orgID    string
	serverID string
	scope    string
	// familyID continues a refresh token family; "" starts one.
	familyID string
	// consumeID is the refresh token this rotation spends; "" for a code.
	consumeID string
	// sessionID is the browser session that consented, and publicSID its
	// public id, the sid claim. amr is how it signed in. All three are
	// empty for client credentials.
	sessionID string
	publicSID string
	amr       []string
	extra     map[string]any
}

var (
	// errSessionEnded is a grant whose consenting session has ended or
	// is no longer on record.
	errSessionEnded = errors.New("the session that granted this access has ended")
	// errRotationRaced is a refresh token that was consumed, revoked or
	// moved to another session between reading it and spending it.
	errRotationRaced = errors.New("the refresh token changed while it was being rotated")
)

// issueToken mints an access token and, for a person who was granted
// offline access, a rotated refresh token.
//
// Checking the consenting session, spending the old refresh token and
// inserting the new one happen in one transaction that holds a share lock
// on the session row. Ending a session updates that row first, so it
// either waits for the rotation and then revokes the child along with the
// family, or finishes first and the rotation sees it ended. A child can
// never be born after the revocation that should have caught it.
func (o *OAuth) issueToken(ctx context.Context, g grant) (*TokenResponse, error) {
	now := o.now()
	aud := o.Issuer + "/mcp"
	if g.serverID != "" {
		aud += "/" + g.serverID
	}
	scopes := scopeList(g.scope)
	claims := map[string]any{
		"iss": o.Issuer, "sub": g.subject, "aud": aud, "org": g.orgID, "client_id": g.clientID,
		"scope": strings.Join(scopes, " "), "jti": o.NewID(),
		"iat": now.Unix(), "exp": now.Add(AccessTokenTTL).Unix(),
	}
	if g.serverID != "" {
		claims["mcp_server"] = g.serverID
	}
	if g.publicSID != "" {
		claims[claimSID] = g.publicSID
	}
	if len(g.amr) > 0 {
		claims[claimAMR] = g.amr
	}
	for k, v := range g.extra {
		claims[k] = v
	}
	// Signed before the transaction, so no lock is held across the
	// keyring; a token signed for a grant the transaction refuses is
	// dropped unseen.
	access, err := o.Keys.Sign(ctx, claims)
	if err != nil {
		return nil, err
	}
	out := &TokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: int(AccessTokenTTL.Seconds()), Scope: strings.Join(scopes, " "),
		Issued: Issued{OrgID: g.orgID, UserID: g.userID, Subject: g.subject, ClientID: g.clientID, ServerID: g.serverID}}
	withRefresh := g.userID != "" && containsString(scopes, ScopeOfflineAccess)
	if g.sessionID == "" && g.consumeID == "" && !withRefresh {
		return out, nil
	}
	var refresh string
	var hash [32]byte
	if withRefresh {
		refresh = randomString(40)
		hash = sha256.Sum256([]byte(refresh))
	}
	err = o.DB.Bypass(ctx, "oauth-issue", func(tx pgx.Tx) error {
		if g.sessionID != "" {
			var revoked *time.Time
			err := tx.QueryRow(ctx, `SELECT revoked_at FROM sessions WHERE id = $1 FOR SHARE`, g.sessionID).Scan(&revoked)
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && revoked != nil) {
				return errSessionEnded
			}
			if err != nil {
				return err
			}
		}
		if g.consumeID != "" {
			tag, err := tx.Exec(ctx, `UPDATE oauth_refresh_tokens SET consumed_at = now()
				WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL AND session_id IS NOT DISTINCT FROM NULLIF($2,'')`,
				g.consumeID, g.sessionID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return errRotationRaced
			}
		}
		if !withRefresh {
			return nil
		}
		id := o.NewID()
		familyID := g.familyID
		if familyID == "" {
			familyID = id
		}
		amr := g.amr
		if amr == nil {
			amr = []string{}
		}
		_, err := tx.Exec(ctx, `INSERT INTO oauth_refresh_tokens (id, token_hash, family_id, client_id, user_id, organization_id, server_id, scope, expires_at, session_id, amr)
			VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9,NULLIF($10,''),$11)`,
			id, hash[:], familyID, g.clientID, g.userID, g.orgID, g.serverID, strings.Join(scopes, " "), now.Add(RefreshTokenTTL),
			g.sessionID, amr)
		return err
	})
	if errors.Is(err, errSessionEnded) {
		if g.familyID != "" {
			o.revokeFamily(ctx, g.familyID)
		}
		return nil, oauthErr("invalid_grant", errSessionEnded.Error(), 400)
	}
	if err != nil {
		return nil, err
	}
	out.RefreshToken = refresh
	return out, nil
}

// Revocation is what a revoke request ended.
type Revocation struct {
	OrgID    string
	UserID   string
	ClientID string
	FamilyID string
}

// Revoke implements RFC 7009. The endpoint always reports success, since
// telling a caller that a token did not exist leaks information; the
// return value is for the audit trail, and is nil when nothing live was
// revoked.
func (o *OAuth) Revoke(ctx context.Context, token string) *Revocation {
	hash := sha256.Sum256([]byte(token))
	var out *Revocation
	_ = o.DB.Bypass(ctx, "oauth-revoke", func(tx pgx.Tx) error {
		var r Revocation
		err := tx.QueryRow(ctx, `WITH revoked AS (
				UPDATE oauth_refresh_tokens SET revoked_at = now()
				WHERE revoked_at IS NULL AND family_id = (SELECT family_id FROM oauth_refresh_tokens WHERE token_hash = $1)
				RETURNING organization_id, user_id, client_id, family_id)
			SELECT organization_id, user_id, client_id, family_id FROM revoked LIMIT 1`, hash[:]).
			Scan(&r.OrgID, &r.UserID, &r.ClientID, &r.FamilyID)
		if err == nil {
			out = &r
		}
		return nil
	})
	return out
}

// Introspection is the RFC 7662 response.
type Introspection struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Sub      string `json:"sub,omitempty"`
	Aud      string `json:"aud,omitempty"`
	Org      string `json:"org,omitempty"`
	Exp      int64  `json:"exp,omitempty"`
	TokenTyp string `json:"token_type,omitempty"`
	// Sid and AMR are present for a token from the authorization code
	// grant: the browser session that consented and how it signed in.
	Sid string   `json:"sid,omitempty"`
	AMR []string `json:"amr,omitempty"`
	// Server is the MCP server the token is bound to, for the caller to
	// check the introspecting credential against; it is already in aud.
	Server string `json:"-"`
}

// Introspect reports whether an access token is currently valid.
func (o *OAuth) Introspect(ctx context.Context, token string) *Introspection {
	claims, err := o.Keys.Verify(ctx, token)
	if err != nil {
		return &Introspection{Active: false}
	}
	exp, _ := claims["exp"].(float64)
	if int64(exp) < o.now().Unix() {
		return &Introspection{Active: false}
	}
	if err := o.checkServiceAccount(ctx, claims); err != nil {
		return &Introspection{Active: false}
	}
	if err := o.checkSession(ctx, claims); err != nil {
		return &Introspection{Active: false}
	}
	str := func(k string) string { v, _ := claims[k].(string); return v }
	return &Introspection{Active: true, Scope: str("scope"), ClientID: str("client_id"), Sub: str("sub"),
		Aud: str("aud"), Org: str("org"), Exp: int64(exp), TokenTyp: "Bearer",
		Sid: str(claimSID), AMR: stringList(claims[claimAMR]), Server: str("mcp_server")}
}

// PrincipalFromToken validates an access token for the MCP endpoint.
func (o *OAuth) PrincipalFromToken(ctx context.Context, token string) (*authz.Principal, error) {
	claims, err := o.Keys.Verify(ctx, token)
	if err != nil {
		return nil, ErrInvalidKey
	}
	exp, _ := claims["exp"].(float64)
	if int64(exp) < o.now().Unix() {
		return nil, ErrKeyExpired
	}
	str := func(k string) string { v, _ := claims[k].(string); return v }
	raw := str("sub")
	kind := authz.KindUser
	sub := strings.TrimPrefix(raw, "user_")
	if strings.HasPrefix(raw, "svc_") {
		kind, sub = authz.KindServiceAccount, strings.TrimPrefix(raw, "svc_")
	}
	if sub == "" || sub == raw || str("org") == "" {
		return nil, ErrInvalidKey
	}
	if err := o.checkServiceAccount(ctx, claims); err != nil {
		return nil, err
	}
	if err := o.checkSession(ctx, claims); err != nil {
		return nil, err
	}
	return &authz.Principal{
		Kind: kind, ID: sub, OrgID: str("org"), ServerID: str("mcp_server"),
		Scopes: scopeList(str("scope")), AuthMethod: "oauth_at",
	}, nil
}

// checkServiceAccount refuses a service account's token once the account
// is disabled or deleted, or was disabled after the token was issued, even
// though the token has not expired. A token without the epoch claim was
// issued before epochs existed and counts as epoch 0. Any other subject
// passes.
func (o *OAuth) checkServiceAccount(ctx context.Context, claims map[string]any) error {
	sub, _ := claims["sub"].(string)
	id, ok := strings.CutPrefix(sub, "svc_")
	if !ok {
		return nil
	}
	if o.Accounts == nil {
		return ErrInvalidKey
	}
	org, _ := claims["org"].(string)
	epoch, active, err := o.Accounts.ServiceAccountTokenEpoch(ctx, org, id)
	if err != nil || !active {
		return ErrInvalidKey
	}
	got, _ := claims[claimEpoch].(float64)
	if int(got) != epoch {
		return ErrInvalidKey
	}
	return nil
}

// checkSession refuses a token whose browser session has ended, so that
// signing out, ending a session or deactivating its person cuts off the
// access tokens it led to at once rather than when they expire. A token
// without a sid passes: it came from client credentials, or was issued
// before tokens named their session.
func (o *OAuth) checkSession(ctx context.Context, claims map[string]any) error {
	sid, _ := claims[claimSID].(string)
	if sid == "" {
		return nil
	}
	if o.Sessions == nil {
		return ErrInvalidKey
	}
	ended, err := o.Sessions.SessionEnded(ctx, sid)
	if err != nil || ended {
		return ErrInvalidKey
	}
	return nil
}

// stringList reads a JSON array of strings out of a decoded claim.
func stringList(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Metadata is the RFC 8414 authorization server document.
func (o *OAuth) Metadata() map[string]any {
	return map[string]any{
		"issuer":                                         o.Issuer,
		"authorization_endpoint":                         o.Issuer + "/oauth/authorize",
		"token_endpoint":                                 o.Issuer + "/oauth/token",
		"registration_endpoint":                          o.Issuer + "/oauth/register",
		"revocation_endpoint":                            o.Issuer + "/oauth/revoke",
		"introspection_endpoint":                         o.Issuer + "/oauth/introspect",
		"jwks_uri":                                       o.Issuer + "/.well-known/jwks.json",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token", "client_credentials"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_basic", "client_secret_post"},
		"scopes_supported":                               []string{authz.ScopeToolsRead, authz.ScopeToolsInvoke, ScopeOfflineAccess},
		"authorization_response_iss_parameter_supported": true,
		"service_documentation":                          "https://supermcp.dev/docs/mcp-clients",
	}
}

// ProtectedResourceMetadata is the RFC 9728 document for one MCP server.
func (o *OAuth) ProtectedResourceMetadata(serverID string) map[string]any {
	resource := o.Issuer + "/mcp"
	if serverID != "" {
		resource += "/" + serverID
	}
	return map[string]any{
		"resource":                 resource,
		"authorization_servers":    []string{o.Issuer},
		"scopes_supported":         []string{authz.ScopeToolsRead, authz.ScopeToolsInvoke},
		"bearer_methods_supported": []string{"header"},
	}
}

// PruneExpired removes spent codes, sessions and tokens.
func (o *OAuth) PruneExpired(ctx context.Context) error {
	return o.DB.Bypass(ctx, "oauth-prune", func(tx pgx.Tx) error {
		for _, q := range []string{
			`DELETE FROM oauth_sessions WHERE expires_at < now()`,
			`DELETE FROM oauth_codes WHERE expires_at < now() - interval '1 day'`,
			`DELETE FROM oauth_refresh_tokens WHERE expires_at < now() - interval '7 days'`,
		} {
			if _, err := tx.Exec(ctx, q); err != nil {
				return err
			}
		}
		return nil
	})
}

func scopeList(scope string) []string {
	fields := strings.Fields(scope)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		switch f {
		case authz.ScopeToolsRead, authz.ScopeToolsInvoke, ScopeOfflineAccess:
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		// A client that asks for nothing gets the read and invoke scopes,
		// which is what an MCP client is for.
		return []string{authz.ScopeToolsRead, authz.ScopeToolsInvoke}
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}
