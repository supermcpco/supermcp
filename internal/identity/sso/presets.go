package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// preset is what an administrator does not have to type. Everything a
// preset sets can still be overridden field by field.
type preset struct {
	Label       string
	Protocol    string
	Scopes      []string
	GroupsClaim string
	// fill applies endpoints a preset knows without discovery.
	fill func(p *Provider)
}

var presets = map[string]preset{
	// Entra ID (Azure AD). The issuer names the tenant, so it is supplied.
	// Group claims arrive as object ids unless the app registration is
	// configured to emit names.
	"entra": {Label: "Microsoft Entra ID", Protocol: "oidc",
		Scopes: []string{"openid", "profile", "email"}, GroupsClaim: "groups", fill: func(*Provider) {}},

	"google": {Label: "Google Workspace", Protocol: "oidc",
		Scopes: []string{"openid", "profile", "email"}, GroupsClaim: "", fill: func(p *Provider) {
			if p.Issuer == "" {
				p.Issuer = "https://accounts.google.com"
			}
		}},

	"okta": {Label: "Okta", Protocol: "oidc",
		Scopes: []string{"openid", "profile", "email", "groups"}, GroupsClaim: "groups", fill: func(*Provider) {}},

	"auth0": {Label: "Auth0", Protocol: "oidc",
		Scopes: []string{"openid", "profile", "email"}, GroupsClaim: "", fill: func(*Provider) {}},

	// GitHub is OAuth 2.0 with a user endpoint, not OpenID Connect: there
	// is no ID token and no discovery document.
	"github": {Label: "GitHub", Protocol: "oauth2",
		Scopes: []string{"read:user", "user:email"}, GroupsClaim: "", fill: func(p *Provider) {
			p.AuthorizationEndpoint = "https://github.com/login/oauth/authorize"
			p.TokenEndpoint = "https://github.com/login/oauth/access_token"
			p.UserinfoEndpoint = "https://api.github.com/user"
			p.JWKSURI = ""
			p.Issuer = ""
		}},

	"generic": {Label: "Single sign-on", Protocol: "oidc",
		Scopes: []string{"openid", "profile", "email"}, GroupsClaim: "groups", fill: func(*Provider) {}},
}

// Presets lists what the UI can offer, with the defaults each implies.
func Presets() []map[string]any {
	out := []map[string]any{}
	for _, name := range []string{"entra", "google", "okta", "auth0", "github", "generic"} {
		p := presets[name]
		out = append(out, map[string]any{
			"id": name, "label": p.Label, "protocol": p.Protocol,
			"scopes": p.Scopes, "groupsClaim": p.GroupsClaim,
			"needsIssuer": p.Protocol == "oidc" && name != "google",
		})
	}
	return out
}

// discoveryTTL is how long a cached discovery document is trusted. The
// endpoints in it change rarely; the signing keys behind jwks_uri rotate
// and are cached separately and more briefly.
const discoveryTTL = 24 * time.Hour

// ensureEndpoints fills the provider's endpoints from its discovery
// document when they are missing or stale, and writes them back so the
// next sign-in does not have to fetch them.
func (s *Service) ensureEndpoints(ctx context.Context, p *Provider) error {
	fresh := p.DiscoveredAt != nil && s.now().Sub(*p.DiscoveredAt) < discoveryTTL
	if p.AuthorizationEndpoint != "" && p.TokenEndpoint != "" && (fresh || p.Protocol == "oauth2") {
		return nil
	}
	if p.Protocol != "oidc" || p.Issuer == "" {
		if p.AuthorizationEndpoint == "" || p.TokenEndpoint == "" {
			return fmt.Errorf("%w: this provider has no authorization or token endpoint configured", ErrProviderFailed)
		}
		return nil
	}
	doc, err := s.discover(ctx, p.Issuer)
	if err != nil {
		// Configured endpoints are better than no sign-in at all when the
		// metadata endpoint is briefly unreachable.
		if p.AuthorizationEndpoint != "" && p.TokenEndpoint != "" {
			return nil
		}
		return err
	}
	p.AuthorizationEndpoint, p.TokenEndpoint = doc.Authorization, doc.Token
	p.UserinfoEndpoint, p.JWKSURI = doc.Userinfo, doc.JWKS
	now := s.now()
	p.DiscoveredAt = &now
	return s.DB.Pre(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT auth_idp_discovery($1,$2,$3,$4,$5)`,
			p.ID, doc.Authorization, doc.Token, doc.Userinfo, doc.JWKS)
		return err
	})
}

type discoveryDoc struct {
	Issuer        string `json:"issuer"`
	Authorization string `json:"authorization_endpoint"`
	Token         string `json:"token_endpoint"`
	Userinfo      string `json:"userinfo_endpoint"`
	JWKS          string `json:"jwks_uri"`
}

func (s *Service) discover(ctx context.Context, issuer string) (*discoveryDoc, error) {
	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	var doc discoveryDoc
	if err := s.doJSON(req, &doc); err != nil {
		return nil, err
	}
	if doc.Authorization == "" || doc.Token == "" {
		return nil, fmt.Errorf("%w: %s published no usable metadata", ErrProviderFailed, issuer)
	}
	// An issuer that does not match the document it serves is either
	// misconfigured or not the issuer we think it is.
	if doc.Issuer != "" && strings.TrimSuffix(doc.Issuer, "/") != strings.TrimSuffix(issuer, "/") {
		return nil, fmt.Errorf("%w: %s publishes metadata for %s", ErrProviderFailed, issuer, doc.Issuer)
	}
	return &doc, nil
}

// Discover checks a provider's metadata without saving anything, so the
// configuration screen can tell an administrator it works before they
// commit to it.
func (s *Service) Discover(ctx context.Context, issuer string) (map[string]string, error) {
	doc, err := s.discover(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"issuer": doc.Issuer, "authorizationEndpoint": doc.Authorization, "tokenEndpoint": doc.Token,
		"userinfoEndpoint": doc.Userinfo, "jwksUri": doc.JWKS,
	}, nil
}

var _ = json.Marshal
