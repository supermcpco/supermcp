package sso

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
)

// RevisionKind is what the revision history calls an OIDC or OAuth 2.0
// provider. SAML providers are a kind of their own: they live in another
// table, with other ids.
const RevisionKind = "identity_provider"

// Recorder is the part of the revision history this package needs. It is
// an interface so the dependency points this way and not the other.
type Recorder interface {
	Record(ctx context.Context, tx pgx.Tx, kind, entityID, action string, entity any, diff *audit.Diff, actorID string) error
	// RecordBaseline records entity as the first revision when entityID
	// has none yet, and does nothing otherwise.
	RecordBaseline(ctx context.Context, tx pgx.Tx, kind, entityID string, entity any) error
}

// Snapshot is a provider as its history records it: what an administrator
// configured, and nothing the service found out for itself.
//
// The client secret is not in it, sealed or otherwise. A restore therefore
// keeps whatever secret is stored when it runs: the secret an earlier
// version used may have been revoked at the provider since, and a sealed
// copy kept here would be a second place a secret lives that rotating it
// does not reach.
//
// The endpoints are nested because the history digests a top-level field
// whose name looks like a credential, and "tokenEndpoint" does. A digest
// cannot be put back.
type Snapshot struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Preset          string    `json:"preset"`
	Protocol        string    `json:"protocol"`
	Issuer          string    `json:"issuer"`
	ClientID        string    `json:"clientId"`
	Scopes          []string  `json:"scopes"`
	Endpoints       Endpoints `json:"endpoints"`
	AllowedDomains  []string  `json:"allowedDomains"`
	JITProvisioning bool      `json:"jitProvisioning"`
	DefaultRoleID   string    `json:"defaultRoleId,omitempty"`
	GroupsClaim     string    `json:"groupsClaim,omitempty"`
	Enabled         bool      `json:"enabled"`
	// MFA is the second-factor rule. Nil in a revision recorded before
	// providers had one, and restoring such a revision keeps the rule the
	// provider has now.
	MFA *MFARule `json:"mfa,omitempty"`
}

// Endpoints are the provider's URLs as configured. Empty ones are filled
// from discovery at sign-in.
type Endpoints struct {
	Authorization string `json:"authorization,omitempty"`
	Token         string `json:"token,omitempty"`
	Userinfo      string `json:"userinfo,omitempty"`
	JWKS          string `json:"jwks,omitempty"`
}

// SnapshotOf is the provider as its history records it.
func SnapshotOf(p *Provider) Snapshot {
	return Snapshot{ID: p.ID, Name: p.Name, Preset: p.Preset, Protocol: p.Protocol, Issuer: p.Issuer,
		ClientID: p.ClientID, Scopes: nonNil(p.Scopes),
		Endpoints: Endpoints{Authorization: p.AuthorizationEndpoint, Token: p.TokenEndpoint,
			Userinfo: p.UserinfoEndpoint, JWKS: p.JWKSURI},
		AllowedDomains: nonNil(p.AllowedDomains), JITProvisioning: p.JITProvisioning,
		DefaultRoleID: p.DefaultRoleID, GroupsClaim: p.GroupsClaim, Enabled: p.Enabled,
		MFA: &MFARule{AMR: nonNil(p.MFA.AMR), ACR: nonNil(p.MFA.ACR)}}
}

// Input is the snapshot as an update, with no client secret, so the one
// stored is kept.
func (s Snapshot) Input() Input {
	return Input{Name: s.Name, Preset: s.Preset, Issuer: s.Issuer, ClientID: s.ClientID, Scopes: s.Scopes,
		AllowedDomains: s.AllowedDomains, JITProvisioning: s.JITProvisioning, DefaultRoleID: s.DefaultRoleID,
		GroupsClaim: s.GroupsClaim, Enabled: s.Enabled,
		AuthorizationEndpoint: s.Endpoints.Authorization, TokenEndpoint: s.Endpoints.Token,
		UserinfoEndpoint: s.Endpoints.Userinfo, JWKSURI: s.Endpoints.JWKS, MFA: s.MFA}
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
