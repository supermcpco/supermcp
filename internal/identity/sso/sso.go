// Package sso signs people in through their own identity provider.
//
// One code path covers OpenID Connect (Entra, Google, Okta, Auth0 and any
// conforming provider) and GitHub, which is plain OAuth 2.0 with a user
// endpoint instead of an ID token. What a provider tells us about a person
// decides three things: who they are, whether they may sign in at all, and
// which roles they hold. Nothing else is inferred.
package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// Errors a caller distinguishes.
var (
	ErrNotFound       = errors.New("identity provider not found")
	ErrDisabled       = errors.New("this identity provider is turned off")
	ErrStateInvalid   = errors.New("this sign-in link has expired or was already used")
	ErrDomainRefused  = errors.New("this email domain is not allowed to sign in here")
	ErrNoAccount      = errors.New("no account here matches that identity, and provisioning is off")
	ErrEmailMissing   = errors.New("the identity provider did not return a verified email address")
	ErrProviderFailed = errors.New("the identity provider rejected the sign-in")
	// ErrInvalid wraps a configuration the administrator has to correct.
	ErrInvalid = errors.New("the provider configuration is not valid")
	// ErrSecretRequired refuses a change that would send the stored client
	// secret somewhere it has not been sent before.
	ErrSecretRequired = errors.New("this change points the provider at a different issuer or host, " +
		"so it needs the client secret for that provider: the stored one is only ever sent where it was configured to go")
)

// requestTTL bounds how long a sign-in may stay in flight.
const requestTTL = 10 * time.Minute

// Doer is the HTTP client used for provider calls. It is the SSRF-guarded
// client, so a provider URL cannot be pointed at an internal address.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Provider is one configured identity provider.
type Provider struct {
	ID                    string     `json:"id"`
	OrgID                 string     `json:"organizationId"`
	Name                  string     `json:"name"`
	Preset                string     `json:"preset"`
	Protocol              string     `json:"protocol"`
	Issuer                string     `json:"issuer"`
	ClientID              string     `json:"clientId"`
	Scopes                []string   `json:"scopes"`
	AuthorizationEndpoint string     `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string     `json:"tokenEndpoint,omitempty"`
	UserinfoEndpoint      string     `json:"userinfoEndpoint,omitempty"`
	JWKSURI               string     `json:"jwksUri,omitempty"`
	DiscoveredAt          *time.Time `json:"discoveredAt,omitempty"`
	AllowedDomains        []string   `json:"allowedDomains"`
	JITProvisioning       bool       `json:"jitProvisioning"`
	DefaultRoleID         string     `json:"defaultRoleId,omitempty"`
	GroupsClaim           string     `json:"groupsClaim,omitempty"`
	Enabled               bool       `json:"enabled"`
	// MFA decides whether a sign-in through the provider had a second
	// factor. Always empty for plain OAuth 2.0, which has no ID token.
	MFA MFARule `json:"mfa"`

	secretEnc []byte
}

// Listing is a provider as the anonymous sign-in page sees it: a name to
// click, and nothing that describes the configuration.
type Listing struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Preset string `json:"preset"`
	Org    string `json:"organization"`
}

// Result is a completed sign-in.
type Result struct {
	UserID        string
	OrgID         string
	Email         string
	Name          string
	Groups        []string
	ProviderID    string
	ProviderName  string
	RedirectAfter string
	// AuthTime is when the provider says the person authenticated: the
	// auth_time claim of a verified ID token. Nil when the provider did
	// not say, which is always the case for plain OAuth2 (GitHub).
	AuthTime *time.Time
	// Replaces is the session this sign-in was started to re-authenticate,
	// as recorded by Begin; empty for an ordinary sign-in.
	Replaces string
	// MultiFactor is true when the verified ID token met the provider's
	// second-factor rule. Always false without a rule or an ID token.
	MultiFactor bool
	// AuthMethods is the amr claim of the verified ID token, bounded; nil
	// when there was no ID token or it carried no amr. ACR is its acr.
	AuthMethods []string
	ACR         string
}

// Service handles provider configuration and the sign-in exchange.
type Service struct {
	DB        *tenant.DB
	Sealer    *secrets.Sealer
	HTTP      Doer
	NewID     func() string
	PublicURL *url.URL
	// Revisions records each change to a provider beside the change, in
	// the same transaction. Nil records nothing.
	Revisions Recorder

	keys *jwksCache
	now  func() time.Time
}

// New builds the service.
func New(db *tenant.DB, sealer *secrets.Sealer, httpDoer Doer, newID func() string, publicURL *url.URL) *Service {
	return &Service{DB: db, Sealer: sealer, HTTP: httpDoer, NewID: newID, PublicURL: publicURL,
		keys: newJWKSCache(httpDoer), now: time.Now}
}

// RedirectURI is the one URI every provider redirects back to. It carries
// no provider id: the state parameter identifies the sign-in, and a URI
// that varies per provider is one more thing to register.
func (s *Service) RedirectURI() string {
	return strings.TrimSuffix(s.PublicURL.String(), "/") + "/auth/sso/callback"
}

// --- configuration ---------------------------------------------------------

// Input is a provider as an administrator supplies it.
type Input struct {
	Name            string
	Preset          string
	Issuer          string
	ClientID        string
	ClientSecret    string
	Scopes          []string
	AllowedDomains  []string
	JITProvisioning bool
	DefaultRoleID   string
	GroupsClaim     string
	Enabled         bool

	// Only a generic provider needs these; otherwise discovery fills them.
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserinfoEndpoint      string
	JWKSURI               string

	// MFA is the second-factor rule. Nil gives a new OpenID Connect
	// provider DefaultMFARule and leaves an existing provider's rule as it
	// is; an empty rule is no rule.
	MFA *MFARule
}

// Create stores a provider for an organisation.
func (s *Service) Create(ctx context.Context, orgID, actorID string, in Input) (*Provider, error) {
	p, err := s.fromInput(orgID, in)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	p.ID = s.NewID()
	if in.MFA == nil && p.Protocol == "oidc" {
		p.MFA = DefaultMFARule()
	}
	var enc []byte
	if in.ClientSecret != "" {
		if enc, err = s.sealSecret(ctx, orgID, p.ID, in.ClientSecret); err != nil {
			return nil, err
		}
	}
	err = s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity_providers
			(id, organization_id, name, preset, protocol, issuer, client_id, client_secret_enc, scopes,
			 authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri,
			 allowed_domains, jit_provisioning, default_role_id, groups_claim, enabled, created_by, mfa_amr, mfa_acr)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NULLIF($16,''),$17,$18,$19,$20,$21)`,
			p.ID, orgID, p.Name, p.Preset, p.Protocol, p.Issuer, p.ClientID, enc, p.Scopes,
			p.AuthorizationEndpoint, p.TokenEndpoint, p.UserinfoEndpoint, p.JWKSURI,
			p.AllowedDomains, p.JITProvisioning, p.DefaultRoleID, p.GroupsClaim, p.Enabled, actorID,
			p.MFA.AMR, p.MFA.ACR)
		if err != nil {
			return err
		}
		snap := SnapshotOf(p)
		return s.record(ctx, tx, p.ID, "create", snap, audit.Created(snap), actorID)
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Update replaces a provider's configuration, and returns it with the
// configuration it replaced, read under the row lock. An empty client
// secret keeps the stored one: the UI never receives it, so it cannot send
// it back. It does so only while the provider still points where it did:
// a change of issuer, or an endpoint on a host the provider did not use,
// would otherwise hand the stored secret to whoever runs that host, so it
// needs a secret of its own (ErrSecretRequired).
func (s *Service) Update(ctx context.Context, orgID, id, actorID string, in Input) (*Provider, *Provider, error) {
	p, err := s.fromInput(orgID, in)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	p.ID = id
	var enc []byte
	if in.ClientSecret != "" {
		if enc, err = s.sealSecret(ctx, orgID, id, in.ClientSecret); err != nil {
			return nil, nil, err
		}
	}
	var before *Provider
	err = s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		if before, err = lockProvider(ctx, tx, orgID, id); err != nil {
			return err
		}
		if in.ClientSecret == "" && repointed(before, p) {
			return ErrSecretRequired
		}
		if in.MFA == nil && p.Protocol == "oidc" {
			p.MFA = before.MFA
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_providers SET
			name=$3, preset=$4, protocol=$5, issuer=$6, client_id=$7,
			client_secret_enc = COALESCE($8, client_secret_enc),
			scopes=$9, authorization_endpoint=$10, token_endpoint=$11, userinfo_endpoint=$12, jwks_uri=$13,
			allowed_domains=$14, jit_provisioning=$15, default_role_id=NULLIF($16,''), groups_claim=$17,
			enabled=$18, mfa_amr=$19, mfa_acr=$20,
			discovered_at = CASE WHEN issuer = $6 THEN discovered_at END, updated_at = now()
			WHERE id = $1 AND organization_id = $2`,
			id, orgID, p.Name, p.Preset, p.Protocol, p.Issuer, p.ClientID, enc, p.Scopes,
			p.AuthorizationEndpoint, p.TokenEndpoint, p.UserinfoEndpoint, p.JWKSURI,
			p.AllowedDomains, p.JITProvisioning, p.DefaultRoleID, p.GroupsClaim, p.Enabled,
			p.MFA.AMR, p.MFA.ACR); err != nil {
			return err
		}
		snap := SnapshotOf(p)
		if err := s.baseline(ctx, tx, SnapshotOf(before)); err != nil {
			return err
		}
		return s.record(ctx, tx, id, "update", snap, audit.Changes(SnapshotOf(before), snap), actorID)
	})
	if err != nil {
		return nil, nil, err
	}
	return p, before, nil
}

// repointed reports whether an update would send the client secret
// somewhere the stored configuration does not: a different issuer, or an
// endpoint on a host that is neither the issuer's nor one of the stored
// endpoints'. An endpoint left empty is filled from the issuer's own
// discovery document, so it counts as the issuer's.
func repointed(before, after *Provider) bool {
	if after.Issuer != before.Issuer {
		return true
	}
	known := map[string]bool{}
	for _, u := range []string{before.Issuer, before.AuthorizationEndpoint, before.TokenEndpoint,
		before.UserinfoEndpoint, before.JWKSURI} {
		if h := hostOf(u); h != "" {
			known[h] = true
		}
	}
	for _, u := range []string{after.AuthorizationEndpoint, after.TokenEndpoint, after.UserinfoEndpoint, after.JWKSURI} {
		if u == "" {
			continue
		}
		if h := hostOf(u); h == "" || !known[h] {
			return true
		}
	}
	return false
}

// hostOf is a URL's host and port, lower-cased, or empty for one that does
// not parse.
func hostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

// Delete removes a provider. The identities it created stay, so the people
// keep their accounts and their history. The provider's own history stays
// too, but its sealed client secret goes with the row.
func (s *Service) Delete(ctx context.Context, orgID, id, actorID string) error {
	return s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		before, err := lockProvider(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM identity_providers WHERE id = $1 AND organization_id = $2`, id, orgID); err != nil {
			return err
		}
		snap := SnapshotOf(before)
		if err := s.baseline(ctx, tx, snap); err != nil {
			return err
		}
		return s.record(ctx, tx, id, "delete", snap, audit.Deleted(snap), actorID)
	})
}

// lockProvider reads a provider inside the writing transaction and holds
// its row, so the before a revision records is the one the write replaced.
func lockProvider(ctx context.Context, tx pgx.Tx, orgID, id string) (*Provider, error) {
	var p Provider
	err := tx.QueryRow(ctx, `SELECT id, organization_id, name, preset, protocol, issuer, client_id, scopes,
		authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, discovered_at,
		allowed_domains, jit_provisioning, COALESCE(default_role_id,''), groups_claim, enabled,
		COALESCE(mfa_amr,'{}'), COALESCE(mfa_acr,'{}')
		FROM identity_providers WHERE id = $1 AND organization_id = $2 FOR UPDATE`, id, orgID).
		Scan(&p.ID, &p.OrgID, &p.Name, &p.Preset, &p.Protocol, &p.Issuer, &p.ClientID, &p.Scopes,
			&p.AuthorizationEndpoint, &p.TokenEndpoint, &p.UserinfoEndpoint, &p.JWKSURI, &p.DiscoveredAt,
			&p.AllowedDomains, &p.JITProvisioning, &p.DefaultRoleID, &p.GroupsClaim, &p.Enabled,
			&p.MFA.AMR, &p.MFA.ACR)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// baseline records a provider as it stood before its first recorded
// change, for one configured before providers had a history.
func (s *Service) baseline(ctx context.Context, tx pgx.Tx, before Snapshot) error {
	if s.Revisions == nil {
		return nil
	}
	return s.Revisions.RecordBaseline(ctx, tx, RevisionKind, before.ID, before)
}

func (s *Service) record(ctx context.Context, tx pgx.Tx, id, action string, snap Snapshot, diff *audit.Diff, actorID string) error {
	if s.Revisions == nil {
		return nil
	}
	return s.Revisions.Record(ctx, tx, RevisionKind, id, action, snap, diff, actorID)
}

// List returns an organisation's providers, without secrets.
func (s *Service) List(ctx context.Context, orgID string) ([]Provider, error) {
	out := []Provider{}
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, organization_id, name, preset, protocol, issuer, client_id, scopes,
			authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, discovered_at,
			allowed_domains, jit_provisioning, COALESCE(default_role_id,''), groups_claim, enabled,
			COALESCE(mfa_amr,'{}'), COALESCE(mfa_acr,'{}')
			FROM identity_providers WHERE organization_id = $1 ORDER BY name`, orgID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p Provider
			if err := rows.Scan(&p.ID, &p.OrgID, &p.Name, &p.Preset, &p.Protocol, &p.Issuer, &p.ClientID, &p.Scopes,
				&p.AuthorizationEndpoint, &p.TokenEndpoint, &p.UserinfoEndpoint, &p.JWKSURI, &p.DiscoveredAt,
				&p.AllowedDomains, &p.JITProvisioning, &p.DefaultRoleID, &p.GroupsClaim, &p.Enabled,
				&p.MFA.AMR, &p.MFA.ACR); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// Listings names the enabled providers for the sign-in page, which runs
// before anyone has said who they are.
func (s *Service) Listings(ctx context.Context) ([]Listing, error) {
	out := []Listing{}
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, name, preset, organization_name FROM auth_idp_list()`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var l Listing
			if err := rows.Scan(&l.ID, &l.Name, &l.Preset, &l.Org); err != nil {
				return err
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Service) fromInput(orgID string, in Input) (*Provider, error) {
	preset, ok := presets[in.Preset]
	if !ok {
		return nil, fmt.Errorf("unknown provider type %q", in.Preset)
	}
	p := &Provider{
		OrgID: orgID, Name: strings.TrimSpace(in.Name), Preset: in.Preset, Protocol: preset.Protocol,
		Issuer: strings.TrimSuffix(strings.TrimSpace(in.Issuer), "/"), ClientID: strings.TrimSpace(in.ClientID),
		Scopes: in.Scopes, AllowedDomains: lowerAll(in.AllowedDomains), JITProvisioning: in.JITProvisioning,
		DefaultRoleID: in.DefaultRoleID, GroupsClaim: in.GroupsClaim, Enabled: in.Enabled,
		AuthorizationEndpoint: in.AuthorizationEndpoint, TokenEndpoint: in.TokenEndpoint,
		UserinfoEndpoint: in.UserinfoEndpoint, JWKSURI: in.JWKSURI,
	}
	if p.Name == "" {
		p.Name = preset.Label
	}
	if len(p.Scopes) == 0 {
		p.Scopes = preset.Scopes
	}
	if p.GroupsClaim == "" {
		p.GroupsClaim = preset.GroupsClaim
	}
	if p.ClientID == "" {
		return nil, errors.New("a client id is required")
	}
	preset.fill(p)
	if p.Protocol == "oidc" && p.Issuer == "" {
		return nil, errors.New("an issuer URL is required")
	}
	if err := checkIssuerScheme(p.Issuer); err != nil {
		return nil, err
	}
	p.MFA = MFARule{AMR: []string{}, ACR: []string{}}
	if in.MFA != nil {
		rule, err := in.MFA.normalized()
		if err != nil {
			return nil, err
		}
		// Plain OAuth 2.0 issues no ID token, so there is nothing a rule
		// could be compared with.
		if p.Protocol != "oidc" && !rule.Empty() {
			return nil, errors.New("a second-factor rule needs an OpenID Connect provider: " +
				"this one issues no ID token to read it from")
		}
		p.MFA = rule
	}
	return p, nil
}

// checkIssuerScheme refuses a provider reachable over plain http, which
// would put the authorization code and the ID token on the wire in clear.
// Loopback is exempt: that is a provider running on the same machine, for
// development and tests.
func checkIssuerScheme(issuer string) error {
	if issuer == "" || strings.HasPrefix(issuer, "https://") {
		return nil
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return errors.New("the issuer must be a URL")
	}
	host := u.Hostname()
	if u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
		return nil
	}
	return errors.New("the issuer URL must be https")
}

func (s *Service) sealSecret(ctx context.Context, orgID, id, secret string) ([]byte, error) {
	return s.Sealer.Seal(ctx, secrets.ScopeOrg(orgID), []byte(secret),
		secrets.AAD{Table: "identity_providers", Column: "client_secret_enc", RowID: id, OrgID: orgID})
}

func (s *Service) openSecret(ctx context.Context, p *Provider) (string, error) {
	if len(p.secretEnc) == 0 {
		return "", nil
	}
	pt, err := s.Sealer.Open(ctx, p.secretEnc,
		secrets.AAD{Table: "identity_providers", Column: "client_secret_enc", RowID: p.ID, OrgID: p.OrgID})
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// load reads a provider without a tenant: a callback arrives with a state
// parameter and no session.
func (s *Service) load(ctx context.Context, id string) (*Provider, error) {
	var p Provider
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, organization_id, name, preset, protocol, issuer, client_id,
			client_secret_enc, scopes, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri,
			discovered_at, allowed_domains, jit_provisioning, COALESCE(default_role_id,''), groups_claim, enabled,
			mfa_amr, mfa_acr
			FROM auth_idp_load($1)`, id).
			Scan(&p.ID, &p.OrgID, &p.Name, &p.Preset, &p.Protocol, &p.Issuer, &p.ClientID,
				&p.secretEnc, &p.Scopes, &p.AuthorizationEndpoint, &p.TokenEndpoint, &p.UserinfoEndpoint,
				&p.JWKSURI, &p.DiscoveredAt, &p.AllowedDomains, &p.JITProvisioning, &p.DefaultRoleID,
				&p.GroupsClaim, &p.Enabled, &p.MFA.AMR, &p.MFA.ACR)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// --- sign-in ---------------------------------------------------------------

// Begin starts a sign-in and returns the URL to send the browser to.
//
// replaces names the session a re-authentication would replace, and is
// empty for an ordinary sign-in. It is kept on the request row, so the
// callback that answers this sign-in, and no other, reads it back. A
// re-authentication also asks the provider to authenticate the person
// again rather than answer from a sign-in it already holds (prompt=login
// and max_age=0). A provider may ignore both; whether it did is judged
// from the auth_time it returns, not from having asked.
func (s *Service) Begin(ctx context.Context, idpID, redirectAfter, binding, replaces string) (string, error) {
	p, err := s.load(ctx, idpID)
	if err != nil {
		return "", err
	}
	if !p.Enabled {
		return "", ErrDisabled
	}
	if err := s.ensureEndpoints(ctx, p); err != nil {
		return "", err
	}
	state, nonce, verifier := randomString(32), randomString(24), randomString(43)
	challenge := sha256.Sum256([]byte(verifier))
	err = s.DB.Pre(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT auth_sso_request_open($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''))`,
			state, p.ID, nonce, verifier, safeRedirect(redirectAfter), s.now().Add(requestTTL), BindingDigest(binding), replaces)
		return err
	})
	if err != nil {
		return "", err
	}
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {p.ClientID},
		"redirect_uri":  {s.RedirectURI()},
		"scope":         {strings.Join(p.Scopes, " ")},
		"state":         {state},
	}
	if p.Protocol == "oidc" {
		q.Set("nonce", nonce)
		// PKCE is not required of a confidential client, and is free to add.
		q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
		q.Set("code_challenge_method", "S256")
	}
	if replaces != "" {
		q.Set("prompt", "login")
		if p.Protocol == "oidc" {
			q.Set("max_age", "0")
		}
	}
	sep := "?"
	if strings.Contains(p.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return p.AuthorizationEndpoint + sep + q.Encode(), nil
}

// BindingDigest is what the request row holds for the browser's cookie:
// the digest, not the value, so a reader of the table cannot forge the
// cookie that would let them finish somebody else's sign-in.
func BindingDigest(binding string) string {
	if binding == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(binding))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Callback completes a sign-in: it consumes the state, exchanges the code,
// checks what came back, and links the person to an account.
func (s *Service) Callback(ctx context.Context, state, code, binding string) (*Result, error) {
	if state == "" || code == "" {
		return nil, ErrStateInvalid
	}
	var idpID, nonce, verifier, redirectAfter, wantBinding string
	var replaces *string
	var expires time.Time
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT idp_id, nonce, code_verifier, redirect_after, expires_at, binding, replaces_session
			FROM auth_sso_request_take($1)`, state).Scan(&idpID, &nonce, &verifier, &redirectAfter, &expires, &wantBinding, &replaces)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrStateInvalid
	}
	if err != nil {
		return nil, err
	}
	if s.now().After(expires) {
		return nil, ErrStateInvalid
	}
	// The code has to come back to the browser that asked for it. A
	// provider issues one to anybody who signs in, so without this
	// somebody signs in as themselves and hands the callback URL to
	// another person, who is then signed in as them.
	if wantBinding != "" && subtle.ConstantTimeCompare([]byte(wantBinding), []byte(BindingDigest(binding))) != 1 {
		return nil, ErrStateInvalid
	}
	p, err := s.load(ctx, idpID)
	if err != nil {
		return nil, err
	}
	if !p.Enabled {
		return nil, ErrDisabled
	}
	if err := s.ensureEndpoints(ctx, p); err != nil {
		return nil, err
	}
	tok, err := s.exchange(ctx, p, code, verifier)
	if err != nil {
		return nil, err
	}
	claims, err := s.identify(ctx, p, tok, nonce)
	if err != nil {
		return nil, err
	}
	res, err := s.link(ctx, p, claims)
	if err != nil {
		return nil, err
	}
	res.RedirectAfter = redirectAfter
	res.AuthTime = claims.AuthTime
	res.AuthMethods, res.ACR = claims.AMR, claims.ACR
	res.MultiFactor = p.Protocol == "oidc" && p.MFA.Satisfied(claims.AMR, claims.ACR)
	if replaces != nil {
		res.Replaces = *replaces
	}
	return res, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

func (s *Service) exchange(ctx context.Context, p *Provider, code, verifier string) (*tokenResponse, error) {
	secret, err := s.openSecret(ctx, p)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {s.RedirectURI()},
		"client_id":    {p.ClientID},
	}
	if p.Protocol == "oidc" {
		form.Set("code_verifier", verifier)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if secret != "" {
		// Client secret basic is what every provider here accepts; sending
		// it in the body as well is what breaks strict ones.
		req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(secret))
	}
	var out tokenResponse
	if err := s.doJSON(req, &out); err != nil {
		return nil, err
	}
	if out.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrProviderFailed, firstNonEmpty(out.ErrorDesc, out.Error))
	}
	if out.AccessToken == "" && out.IDToken == "" {
		return nil, fmt.Errorf("%w: the token response carried no token", ErrProviderFailed)
	}
	return &out, nil
}

// identity is what a provider told us about the person.
type identityClaims struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
	// AuthTime is read from the verified ID token only. The user
	// endpoint's answer is not signed and says nothing about when anybody
	// authenticated.
	AuthTime *time.Time
	// AMR and ACR are the amr and acr claims, from the verified ID token
	// only, for the same reason: a second factor is judged on them.
	AMR []string
	ACR string
}

// identify turns a token response into claims, verifying the ID token when
// there is one and asking the user endpoint when there is not.
func (s *Service) identify(ctx context.Context, p *Provider, tok *tokenResponse, nonce string) (*identityClaims, error) {
	var claims map[string]any
	var authTime *time.Time
	var amr []string
	var acr string
	if tok.IDToken != "" {
		verified, err := s.keys.verify(ctx, p, tok.IDToken)
		if err != nil {
			return nil, err
		}
		if err := checkIDToken(verified, p, nonce, s.now()); err != nil {
			return nil, err
		}
		claims = verified
		if t, ok := claimTime(verified, "auth_time"); ok && t.Unix() > 0 {
			authTime = &t
		}
		// Read before the user endpoint's answer is merged in below,
		// which fills in the claims the token left out.
		amr = reportedMethods(verified)
		if a, ok := verified["acr"].(string); ok && len(a) <= maxRuleValueLen {
			acr = a
		}
	}
	// Ask the user endpoint when the ID token carried no address, and
	// always for GitHub, which issues no ID token at all.
	if claims == nil || claimString(claims, "email") == "" {
		ui, err := s.userinfo(ctx, p, tok.AccessToken)
		if err != nil {
			return nil, err
		}
		if claims == nil {
			claims = ui
		} else {
			for k, v := range ui {
				if _, ok := claims[k]; !ok {
					claims[k] = v
				}
			}
		}
	}
	out := &identityClaims{
		Subject:  firstNonEmpty(claimString(claims, "sub"), claimString(claims, "oid"), claimString(claims, "id")),
		Email:    strings.ToLower(strings.TrimSpace(claimString(claims, "email"))),
		Name:     firstNonEmpty(claimString(claims, "name"), claimString(claims, "preferred_username")),
		Groups:   claimStrings(claims, p.GroupsClaim),
		AuthTime: authTime,
		AMR:      amr,
		ACR:      acr,
	}
	if out.Subject == "" {
		return nil, fmt.Errorf("%w: no subject claim", ErrProviderFailed)
	}
	if out.Email == "" {
		return nil, ErrEmailMissing
	}
	// A provider that reports the address as unverified is not evidence of
	// who this is, and the address is what links to an existing account.
	if v, ok := claims["email_verified"]; ok && !truthy(v) {
		return nil, ErrEmailMissing
	}
	if !domainAllowed(out.Email, p.AllowedDomains) {
		return nil, ErrDomainRefused
	}
	return out, nil
}

func (s *Service) userinfo(ctx context.Context, p *Provider, accessToken string) (map[string]any, error) {
	if p.UserinfoEndpoint == "" || accessToken == "" {
		return map[string]any{}, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	var out map[string]any
	if err := s.doJSON(req, &out); err != nil {
		return nil, err
	}
	if p.Preset == "github" {
		s.gitHubExtras(ctx, accessToken, out)
	}
	return out, nil
}

// gitHubExtras fills in what GitHub does not put on /user: a private
// primary address, and the teams that stand in for groups.
func (s *Service) gitHubExtras(ctx context.Context, accessToken string, out map[string]any) {
	if claimString(out, "email") == "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+accessToken)
			req.Header.Set("Accept", "application/json")
			var emails []struct {
				Email    string `json:"email"`
				Primary  bool   `json:"primary"`
				Verified bool   `json:"verified"`
			}
			if err := s.doJSON(req, &emails); err == nil {
				for _, e := range emails {
					if e.Primary && e.Verified {
						out["email"] = e.Email
						out["email_verified"] = true
						break
					}
				}
			}
		}
	}
	if id, ok := out["id"]; ok {
		out["sub"] = claimString(map[string]any{"sub": id}, "sub")
	}
}

func (s *Service) doJSON(req *http.Request, out any) error {
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProviderFailed, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProviderFailed, err)
	}
	if resp.StatusCode >= 400 {
		// The body may name the problem; it may also contain the code we
		// just sent, so only the status goes in the message.
		if err := json.Unmarshal(body, out); err == nil {
			return nil // a provider that reports its error as JSON
		}
		return fmt.Errorf("%w: the provider answered %s", ErrProviderFailed, resp.Status)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: the provider's answer was not JSON", ErrProviderFailed)
	}
	return nil
}

// link finds or creates the account behind the claims and syncs the roles
// the provider's groups map to.
func (s *Service) link(ctx context.Context, p *Provider, c *identityClaims) (*Result, error) {
	var userID *string
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT auth_sso_link($1,$2,$3,$4,$5,$6,$7)`,
			p.ID, p.OrgID, c.Subject, c.Email, c.Name, s.NewID(), p.JITProvisioning).Scan(&userID)
	})
	if err != nil {
		return nil, err
	}
	if userID == nil {
		return nil, ErrNoAccount
	}
	res := &Result{UserID: *userID, OrgID: p.OrgID, Email: c.Email, Name: c.Name, Groups: c.Groups,
		ProviderID: p.ID, ProviderName: p.Name}
	if err := s.syncRoles(ctx, p, *userID, c.Groups); err != nil {
		return nil, err
	}
	return res, nil
}

// syncRoles makes the user's provider-sourced bindings match their groups.
// Bindings an administrator made by hand are left alone: the provider owns
// what it granted and nothing else.
func (s *Service) syncRoles(ctx context.Context, p *Provider, userID string, groups []string) error {
	return s.DB.Tx(tenant.WithOrg(ctx, p.OrgID), func(tx pgx.Tx) error {
		want := map[string]bool{}
		if len(groups) > 0 {
			rows, err := tx.Query(ctx, `SELECT DISTINCT role_id FROM role_bindings
				WHERE organization_id = $1 AND principal_kind = 'idp_group' AND principal_id = ANY($2)`, p.OrgID, groups)
			if err != nil {
				return err
			}
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				want[id] = true
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		// A default role covers the case where no group maps to anything,
		// so a first sign-in is not an account that can do nothing.
		if len(want) == 0 && p.DefaultRoleID != "" {
			want[p.DefaultRoleID] = true
		}
		if _, err := tx.Exec(ctx, `DELETE FROM role_bindings
			WHERE organization_id = $1 AND principal_kind = 'user' AND principal_id = $2
			  AND source = 'sso' AND NOT (role_id = ANY($3))`, p.OrgID, userID, keys(want)); err != nil {
			return err
		}
		for roleID := range want {
			if _, err := tx.Exec(ctx, `INSERT INTO role_bindings
				(id, organization_id, principal_kind, principal_id, role_id, source, external_ref)
				VALUES ($1,$2,'user',$3,$4,'sso',$5)
				ON CONFLICT (organization_id, principal_kind, principal_id, role_id, scope_kind, scope_id, source)
				DO NOTHING`, s.NewID(), p.OrgID, userID, roleID, p.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

// --- helpers ---------------------------------------------------------------

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(s, "@"))); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func domainAllowed(email string, domains []string) bool {
	if len(domains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	got := email[at+1:]
	for _, d := range domains {
		if got == d || strings.HasSuffix(got, "."+d) {
			return true
		}
	}
	return false
}

// safeRedirect keeps a post-sign-in destination inside this site. A
// backslash counts as a slash: a browser reads "/\\evil.example" as
// protocol-relative and leaves the site, which is the same open redirect
// that "//evil.example" would be.
func safeRedirect(s string) string {
	if len(s) < 1 || s[0] != '/' {
		return ""
	}
	if len(s) > 1 && (s[1] == '/' || s[1] == '\\') {
		return ""
	}
	return s
}

// ConfirmsSignIn reports whether signing in through this provider can
// say when the person authenticated: an OpenID Connect provider returns
// auth_time when asked, a plain OAuth2 provider such as GitHub cannot.
func (s *Service) ConfirmsSignIn(ctx context.Context, idpID string) (bool, error) {
	p, err := s.load(ctx, idpID)
	if err != nil {
		return false, err
	}
	return p.Protocol == "oidc", nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func claimString(m map[string]any, key string) string {
	if key == "" {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case json.Number:
		return v.String()
	}
	return ""
}

func claimStrings(m map[string]any, key string) []string {
	if key == "" {
		return nil
	}
	switch v := m[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return strings.Split(v, ",")
	}
	return nil
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true" || x == "1"
	}
	return false
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}
