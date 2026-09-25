package saml

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
)

// RevisionKind is what the revision history calls a SAML provider. OIDC
// providers are a kind of their own: they live in another table, with
// other ids.
const RevisionKind = "saml_provider"

// Recorder is the part of the revision history this package needs. It is
// an interface so the dependency points this way and not the other.
type Recorder interface {
	Record(ctx context.Context, tx pgx.Tx, kind, entityID, action string, entity any, diff *audit.Diff, actorID string) error
	// RecordBaseline records entity as the first revision when entityID
	// has none yet, and does nothing otherwise.
	RecordBaseline(ctx context.Context, tx pgx.Tx, kind, entityID string, entity any) error
}

// Snapshot is a provider as its history records it.
//
// Unlike the provider the API serves, it carries the identity provider's
// certificates: they are public, and they are what a restore needs to
// trust the same signer the version being restored trusted. Our signing
// certificate is recorded so a rotation shows in the history; our private
// key is not, sealed or otherwise, and a restore leaves the key pair as it
// is.
type Snapshot struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	EntityID          string     `json:"entityId"`
	CertificatePEM    string     `json:"certificatePem"`
	IDPEntityID       string     `json:"idpEntityId"`
	IDPSSOURL         string     `json:"idpSsoUrl"`
	IDPCertificates   []string   `json:"idpCertificates"`
	MetadataURL       string     `json:"metadataUrl,omitempty"`
	MetadataFetchedAt *time.Time `json:"metadataFetchedAt,omitempty"`
	EmailAttribute    string     `json:"emailAttribute,omitempty"`
	NameAttribute     string     `json:"nameAttribute,omitempty"`
	GroupsAttribute   string     `json:"groupsAttribute,omitempty"`
	AllowedDomains    []string   `json:"allowedDomains"`
	JITProvisioning   bool       `json:"jitProvisioning"`
	DefaultRoleID     string     `json:"defaultRoleId,omitempty"`
	Enabled           bool       `json:"enabled"`
}

// SnapshotOf is the provider as its history records it.
func SnapshotOf(p *Provider) Snapshot {
	return Snapshot{ID: p.ID, Name: p.Name, EntityID: p.EntityID, CertificatePEM: p.CertificatePEM,
		IDPEntityID: p.IDPEntityID, IDPSSOURL: p.IDPSSOURL, IDPCertificates: nonNil(p.IDPCertificates),
		MetadataURL: p.MetadataURL, MetadataFetchedAt: p.MetadataFetchedAt,
		EmailAttribute: p.EmailAttribute, NameAttribute: p.NameAttribute, GroupsAttribute: p.GroupsAttribute,
		AllowedDomains: nonNil(p.AllowedDomains), JITProvisioning: p.JITProvisioning,
		DefaultRoleID: p.DefaultRoleID, Enabled: p.Enabled}
}

// provider is the snapshot as the columns an edit writes.
func (s Snapshot) provider(orgID, id string) *Provider {
	return &Provider{ID: id, OrgID: orgID, Name: s.Name, EntityID: s.EntityID,
		IDPEntityID: s.IDPEntityID, IDPSSOURL: s.IDPSSOURL, IDPCertificates: nonNil(s.IDPCertificates),
		MetadataURL: s.MetadataURL, MetadataFetchedAt: s.MetadataFetchedAt,
		EmailAttribute: s.EmailAttribute, NameAttribute: s.NameAttribute, GroupsAttribute: s.GroupsAttribute,
		AllowedDomains: lowerAll(s.AllowedDomains), JITProvisioning: s.JITProvisioning,
		DefaultRoleID: s.DefaultRoleID, Enabled: s.Enabled}
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
