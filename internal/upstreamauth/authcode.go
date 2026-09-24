package upstreamauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/tenant"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

// ---------------------------------------------------------------------------
// OAuth2 (authorization_code)
//
// The other two grants in this package run unattended: both start from
// something an administrator typed into the credentials form. This one
// cannot. A person has to approve access at the vendor, in a browser, and
// the only thing that survives that detour is the refresh token the vendor
// hands back at the end.
//
// So nothing here renews anything. It obtains that first refresh token and
// leaves it where flows.go already looks for it, after which the connector
// is an ordinary refresh-token connector and the machinery that was
// already working takes over.

// consentTTL bounds how long a consent may stay in flight. An
// administrator has to sign in at the vendor and read a permissions
// screen, which is minutes; a code that outlives its consent is a
// credential lying about waiting to be used.
const consentTTL = 10 * time.Minute

// Errors a caller distinguishes. Each one names something an
// administrator can act on, and none of them carries the vendor's own
// words: those may describe an internal address.
var (
	// ErrConsentInvalid covers every reason a state is not a consent this
	// instance is waiting for: never issued, already spent, or expired.
	// They are deliberately one error — saying which would tell whoever
	// sent it which states exist.
	ErrConsentInvalid = errors.New("this authorisation link has expired or was already used")
	// ErrNoRefreshToken is the vendor issuing an access token and nothing
	// to renew it with. Said now, loudly, because the alternative is a
	// connector that works this afternoon and fails tonight.
	ErrNoRefreshToken = errors.New("the vendor issued no refresh token, so this connector cannot stay connected")
	// ErrVendorRejected is anything the vendor refused or garbled.
	ErrVendorRejected = errors.New("the vendor rejected the authorisation")
	// ErrNotAuthCode is a connector whose auth block does not describe
	// this flow at all.
	ErrNotAuthCode = errors.New("this connector does not use the oauth2 authorization code grant")
)

// Consent is one authorisation in flight: what the callback will need
// when the browser comes back with a code.
type Consent struct {
	State       string
	ConnectorID string
	// OrgID owns the connector. The Postgres store reads it back from the
	// connector when the consent is spent, rather than keeping a second
	// copy of something that could only ever disagree with the first.
	OrgID string
	// Verifier is the PKCE code verifier. It never leaves this instance,
	// which is the whole point of it.
	Verifier  string
	ActorID   string
	ExpiresAt time.Time
}

// ConsentStore remembers authorisations in flight.
//
// The implementations live below rather than in the connector package
// because a consent belongs to the flow, not to the connector: it exists
// for ten minutes and refers to a connector, and a connector knows
// nothing about it.
type ConsentStore interface {
	Create(ctx context.Context, c Consent) error
	// Consume returns the consent and marks it spent in the same
	// statement. A state that was never issued, or has already been
	// consumed, yields ErrConsentInvalid.
	Consume(ctx context.Context, state string) (Consent, error)
}

// Params are the vendor's half of the flow, read from a connector's auth
// block with its credentials rendered in. They are passed to Begin and
// again to Exchange rather than kept in the consent row: the client
// secret is already sealed once, under the connector's own key, and a
// second copy in a short-lived table would be a second thing to protect.
type Params struct {
	ConnectorID      string
	OrgID            string
	ClientID         string
	ClientSecret     string
	AuthorizationURL string
	TokenURL         string
	Scopes           []string
	ClientAuth       string // basic | body, as the adapter declares it
	ExtraTokenParams map[string]string
}

// AuthCode drives the authorization code grant for upstream connectors.
type AuthCode struct {
	store       ConsentStore
	http        engine.HTTPDoer
	redirectURI string
	now         func() time.Time
}

// NewAuthCode builds the flow. The HTTP client must be the SSRF-guarded
// one: the token endpoint comes from an adapter, and an adapter is not
// evidence that a URL points outwards.
func NewAuthCode(store ConsentStore, doer engine.HTTPDoer, publicURL *url.URL) *AuthCode {
	base := ""
	if publicURL != nil {
		base = strings.TrimSuffix(publicURL.String(), "/")
	}
	return &AuthCode{store: store, http: doer, redirectURI: base + "/auth/connectors/callback", now: time.Now}
}

// RedirectURI is the one URI every vendor redirects back to, and the one
// thing an administrator registers with them. It carries no connector id:
// the state identifies the consent, and a URI that varied per connector
// would have to be registered again for every connector installed.
func (a *AuthCode) RedirectURI() string { return a.redirectURI }

// ParamsFor reads the flow's parameters out of a resolved connector,
// rendering the {{env.*}} placeholders in its auth block against the
// credentials that were decrypted with it.
func ParamsFor(conn *engine.Connector, orgID string, env map[string]string) (Params, error) {
	auth := conn.Auth
	if auth.Type != adapter.AuthOAuth2 || auth.Grant != "authorization_code" {
		return Params{}, ErrNotAuthCode
	}
	p := Params{ConnectorID: conn.ID, OrgID: orgID, Scopes: auth.Scopes, ClientAuth: auth.ClientAuth}
	var err error
	if p.ClientID, err = renderEnv(auth.ClientID, env); err != nil {
		return Params{}, fmt.Errorf("clientId: %w", err)
	}
	if p.ClientSecret, err = renderEnv(auth.ClientSecret, env); err != nil {
		return Params{}, fmt.Errorf("clientSecret: %w", err)
	}
	if p.AuthorizationURL, err = renderEnv(auth.AuthorizationURL, env); err != nil {
		return Params{}, fmt.Errorf("authorizationUrl: %w", err)
	}
	if p.TokenURL, err = renderEnv(auth.TokenURL, env); err != nil {
		return Params{}, fmt.Errorf("tokenUrl: %w", err)
	}
	if p.ExtraTokenParams, err = renderEnvMap(auth.ExtraTokenParams, env); err != nil {
		return Params{}, fmt.Errorf("extraTokenParams: %w", err)
	}
	if err := p.validate(); err != nil {
		return Params{}, err
	}
	return p, nil
}

func (p Params) validate() error {
	if p.ClientID == "" {
		return errors.New("oauth2 authorization_code: clientId is not set")
	}
	if p.AuthorizationURL == "" || p.TokenURL == "" {
		return errors.New("oauth2 authorization_code: authorizationUrl and tokenUrl are required")
	}
	if err := checkEndpoint("authorizationUrl", p.AuthorizationURL); err != nil {
		return err
	}
	return checkEndpoint("tokenUrl", p.TokenURL)
}

// checkEndpoint refuses an endpoint that is not https. Both URLs come from
// an adapter: over plain http the authorization code, the client secret
// and the refresh token would all be on the wire in clear. Loopback is
// exempt, which is a vendor stub on this machine, for development and
// tests.
func checkEndpoint(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("oauth2 authorization_code: %s is not a URL", field)
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && isLoopback(u.Hostname()):
		return nil
	}
	return fmt.Errorf("oauth2 authorization_code: %s must be https", field)
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// Begin records a consent and returns the URL to send the browser to.
func (a *AuthCode) Begin(ctx context.Context, p Params, actorID string) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	verifier := randomToken() + randomToken() // PKCE wants 43 characters or more
	sum := sha256.Sum256([]byte(verifier))
	c := Consent{
		State: randomToken(), ConnectorID: p.ConnectorID, OrgID: p.OrgID,
		Verifier: verifier, ActorID: actorID, ExpiresAt: a.now().Add(consentTTL),
	}
	if err := a.store.Create(ctx, c); err != nil {
		return "", fmt.Errorf("record the consent: %w", err)
	}
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {p.ClientID},
		"redirect_uri":  {a.redirectURI},
		"state":         {c.State},
		// PKCE always. The adapter format has nowhere to say whether a
		// vendor supports it, and a challenge a vendor ignores costs
		// nothing, while a missing one leaves the code interceptable by
		// anything that can see the redirect.
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	// Exactly the scopes the adapter declares. A consent screen that asks
	// for more than the tools use is one an administrator is right to
	// refuse, and asking for less means failures at call time.
	if len(p.Scopes) > 0 {
		q.Set("scope", strings.Join(p.Scopes, " "))
	}
	sep := "?"
	if strings.Contains(p.AuthorizationURL, "?") {
		sep = "&"
	}
	return p.AuthorizationURL + sep + q.Encode(), nil
}

// Consume spends the state the callback arrived with.
func (a *AuthCode) Consume(ctx context.Context, state string) (Consent, error) {
	if state == "" {
		return Consent{}, ErrConsentInvalid
	}
	c, err := a.store.Consume(ctx, state)
	if err != nil {
		return Consent{}, err
	}
	if a.now().After(c.ExpiresAt) {
		return Consent{}, ErrConsentInvalid
	}
	return c, nil
}

// Exchange trades the vendor's code for tokens. The returned token
// always carries a refresh token; without one there is nothing worth
// storing, and the caller is told so rather than finding out hours later.
func (a *AuthCode) Exchange(ctx context.Context, p Params, c Consent, code string) (*Token, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if code == "" {
		return nil, fmt.Errorf("%w: no authorization code", ErrVendorRejected)
	}
	if a.http == nil {
		return nil, errors.New("oauth2 authorization_code: no HTTP client for the token endpoint")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {a.redirectURI},
		"code_verifier": {c.Verifier},
	}
	// No scope parameter: for this grant the code decides the scopes, and
	// a vendor that sees both is entitled to call them a mismatch.
	headers := http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"},
		"Accept":       {"application/json"},
	}
	// The same rule flows.go uses for the refresh grant, because the
	// refresh grant is what runs next against this same endpoint: what
	// authenticates the client here has to authenticate it there too.
	if p.ClientAuth == "basic" {
		headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(p.ClientID+":"+p.ClientSecret)))
	} else {
		form.Set("client_id", p.ClientID)
		if p.ClientSecret != "" {
			form.Set("client_secret", p.ClientSecret)
		}
	}
	for k, v := range p.ExtraTokenParams {
		form.Set(k, v)
	}
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(body)), nil }
	req.Header = headers
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: the token endpoint could not be reached", ErrVendorRejected)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tr struct {
		AccessToken  string          `json:"access_token"`
		RefreshToken string          `json:"refresh_token"`
		ExpiresIn    json.RawMessage `json:"expires_in"`
		Error        string          `json:"error"`
	}
	_ = json.Unmarshal(data, &tr)
	// The body is not quoted anywhere, here or later. It can hold the code
	// we just sent, and a vendor's description of its own trouble has been
	// known to name the host it was talking to.
	if resp.StatusCode >= 400 || tr.Error != "" {
		return nil, fmt.Errorf("%w: the vendor answered %s (%s)", ErrVendorRejected, resp.Status, truncate(tr.Error, 40))
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("%w: the token response carried no access token", ErrVendorRejected)
	}
	if tr.RefreshToken == "" {
		return nil, ErrNoRefreshToken
	}
	ttl := time.Hour
	if n, err := strconv.ParseFloat(strings.Trim(string(tr.ExpiresIn), `"`), 64); err == nil && n > 0 {
		ttl = time.Duration(n) * time.Second
	}
	return &Token{Access: tr.AccessToken, Refresh: tr.RefreshToken, ExpiresAt: a.now().Add(ttl)}, nil
}

// ---------------------------------------------------------------------------
// Consent stores

// DBConsentStore keeps consents in Postgres.
//
// The callback arrives with a state parameter and no tenant — the vendor
// redirected the browser, and nothing in that request says which
// organisation it belongs to — so both statements go through SECURITY
// DEFINER functions, exactly as the sign-in flow's do in 00005.
type DBConsentStore struct{ DB *tenant.DB }

var _ ConsentStore = (*DBConsentStore)(nil)

// NewDBConsentStore builds the Postgres consent store.
func NewDBConsentStore(db *tenant.DB) *DBConsentStore { return &DBConsentStore{DB: db} }

// Create records a consent in flight.
func (s *DBConsentStore) Create(ctx context.Context, c Consent) error {
	return s.DB.Pre(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT connector_auth_request_create($1,$2,$3,$4,$5)`,
			c.State, c.ConnectorID, c.Verifier, c.ActorID, c.ExpiresAt)
		return err
	})
}

// Consume spends a consent, once.
func (s *DBConsentStore) Consume(ctx context.Context, state string) (Consent, error) {
	var c Consent
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, connector_id, organization_id, code_verifier, actor_id, expires_at
			FROM connector_auth_request_consume($1)`, state).
			Scan(&c.State, &c.ConnectorID, &c.OrgID, &c.Verifier, &c.ActorID, &c.ExpiresAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Consent{}, ErrConsentInvalid
	}
	if err != nil {
		return Consent{}, err
	}
	return c, nil
}

// MemoryConsentStore is an in-process ConsentStore for tests and
// single-node use, in the spirit of MemoryStore above.
type MemoryConsentStore struct {
	mu sync.Mutex
	m  map[string]Consent
}

var _ ConsentStore = (*MemoryConsentStore)(nil)

// NewMemoryConsentStore builds an empty in-process consent store.
func NewMemoryConsentStore() *MemoryConsentStore {
	return &MemoryConsentStore{m: map[string]Consent{}}
}

// Create records a consent in flight.
func (s *MemoryConsentStore) Create(_ context.Context, c Consent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[c.State] = c
	return nil
}

// Consume spends a consent, once.
func (s *MemoryConsentStore) Consume(_ context.Context, state string) (Consent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.m[state]
	if !ok {
		return Consent{}, ErrConsentInvalid
	}
	delete(s.m, state)
	return c, nil
}

// ---------------------------------------------------------------------------
// helpers

// randomToken is 26 base32 characters, about 130 bits.
func randomToken() string { return rand.Text() }

func renderEnv(s string, env map[string]string) (string, error) {
	if s == "" {
		return "", nil
	}
	v, ok, err := tmpl.Render(s, tmpl.Vars{Env: env}, tmpl.Value)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	return tmpl.Stringify(v), nil
}

func renderEnvMap(m adapter.OrderedMap[string], env map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(m.Keys))
	for _, k := range m.Keys {
		v, err := renderEnv(m.Values[k], env)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		if v != "" {
			out[k] = v
		}
	}
	return out, nil
}
