// Package saml signs people in with SAML 2.0.
//
// We are the service provider. Each organisation gets its own entity id,
// its own assertion consumer URL and its own signing key pair, so one
// organisation's federation cannot be used to sign in to another's. What
// the identity provider says about a person decides three things: who
// they are, whether they may sign in at all, and which roles they hold.
// Nothing else is inferred.
//
// The shape deliberately mirrors the OpenID Connect path in the sibling
// sso package: a provider row per organisation, a request row holding the
// sign-in in flight, and a consumer that matches or creates a user and
// hands back a result the HTTP layer turns into a session. What differs
// is what a SAML assertion is: a signed bearer token with a validity
// window, which must be accepted exactly once.
package saml

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// Errors a caller distinguishes. The text is what a person sees, so it
// says what to do next rather than what went wrong internally.
var (
	ErrNotFound       = errors.New("this SAML provider does not exist here")
	ErrDisabled       = errors.New("this identity provider is turned off; ask an administrator to turn it back on")
	ErrNotConfigured  = errors.New("this SAML provider is not finished being set up")
	ErrRequestInvalid = errors.New("this sign-in took too long or was not started here; " +
		"go back to the sign-in page and try again")
	ErrReplayed         = errors.New("this sign-in has already been used; go back to the sign-in page and try again")
	ErrAssertionInvalid = errors.New("the identity provider's response was refused")
	ErrDomainRefused    = errors.New("this email domain is not allowed to sign in here")
	ErrNoAccount        = errors.New("no account here matches that identity, and this provider does not create " +
		"accounts on first sign-in; ask an administrator to invite you")
	ErrEmailMissing = errors.New("the identity provider sent no email address; " +
		"ask an administrator to add an email attribute to the SAML application")
	ErrMetadata = errors.New("the identity provider's metadata could not be read")
)

// requestTTL bounds how long a sign-in may stay in flight. It is longer
// than the OpenID Connect equivalent because a SAML sign-in routinely
// includes a second factor prompt at the provider.
const requestTTL = 15 * time.Minute

// defaultClockSkew is how far apart our clock and the identity
// provider's may be before an assertion inside its validity window is
// refused. Three minutes is what Shibboleth allows and what every
// provider is tested against.
const defaultClockSkew = 3 * time.Minute

// Doer is the HTTP client used to fetch metadata. It is the SSRF-guarded
// client, because the metadata URL comes from whoever is configuring the
// provider.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Provider is one configured identity provider.
type Provider struct {
	ID    string `json:"id"`
	OrgID string `json:"organizationId"`
	Name  string `json:"name"`

	// Our side of the federation, which an administrator registers with
	// their identity provider.
	EntityID       string `json:"entityId"`
	CertificatePEM string `json:"certificatePem"`

	// Their side, read from the metadata document.
	IDPEntityID       string     `json:"idpEntityId"`
	IDPSSOURL         string     `json:"idpSsoUrl"`
	IDPCertificates   []string   `json:"-"`
	MetadataURL       string     `json:"metadataUrl,omitempty"`
	MetadataFetchedAt *time.Time `json:"metadataFetchedAt,omitempty"`

	EmailAttribute  string   `json:"emailAttribute,omitempty"`
	NameAttribute   string   `json:"nameAttribute,omitempty"`
	GroupsAttribute string   `json:"groupsAttribute,omitempty"`
	AllowedDomains  []string `json:"allowedDomains"`
	JITProvisioning bool     `json:"jitProvisioning"`
	DefaultRoleID   string   `json:"defaultRoleId,omitempty"`
	Enabled         bool     `json:"enabled"`

	certDER []byte
	keyEnc  []byte
}

// SignInOption is a provider as the anonymous sign-in page sees it: a name to
// click, and nothing that describes the configuration.
type SignInOption struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Org  string `json:"organization"`
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
	MultiFactor   bool
	RedirectAfter string
}

// Service handles provider configuration and the assertion exchange.
type Service struct {
	DB        *tenant.DB
	Sealer    *secrets.Sealer
	HTTP      Doer
	NewID     func() string
	PublicURL *url.URL

	now func() time.Time
}

// New builds the service.
//
// The clock skew tolerance is set here rather than per provider, and it
// takes effect process-wide: the SAML library exposes it as a package
// variable rather than as a field on the service provider. That is not
// only a limitation to live with — one gateway talks to many identity
// providers but has a single clock, so one tolerance is the honest model.
func New(db *tenant.DB, sealer *secrets.Sealer, httpDoer Doer, newID func() string, publicURL *url.URL) *Service {
	setClockSkew(defaultClockSkew)
	return &Service{DB: db, Sealer: sealer, HTTP: httpDoer, NewID: newID, PublicURL: publicURL, now: time.Now}
}

// --- the URLs we publish ---------------------------------------------------

func (s *Service) base() string { return strings.TrimSuffix(s.PublicURL.String(), "/") }

// ACSURL is where the identity provider posts the assertion.
func (s *Service) ACSURL(id string) string { return s.base() + "/api/v1/auth/saml/" + id + "/acs" }

// MetadataURL is where the identity provider reads our metadata. It is
// also the default entity id: an entity id has to be globally unique and
// a URL that serves the metadata is the one form every provider accepts.
func (s *Service) MetadataURL(id string) string {
	return s.base() + "/api/v1/auth/saml/" + id + "/metadata"
}

// LoginURL starts a sign-in. A browser is sent here, not to the identity
// provider, so that the request we are about to answer is recorded first.
func (s *Service) LoginURL(id string) string { return s.base() + "/api/v1/auth/saml/" + id + "/login" }

// --- configuration ---------------------------------------------------------

// Input is a provider as an administrator supplies it. Exactly one of
// MetadataURL and MetadataXML is needed: the first is refreshed later,
// the second is a paste from a provider that publishes no metadata URL.
type Input struct {
	Name        string
	EntityID    string
	MetadataURL string
	MetadataXML string

	EmailAttribute  string
	NameAttribute   string
	GroupsAttribute string
	AllowedDomains  []string
	JITProvisioning bool
	DefaultRoleID   string
	Enabled         bool
}

// Create stores a provider and generates the key pair we will sign with.
func (s *Service) Create(ctx context.Context, orgID, actorID string, in Input) (*Provider, error) {
	id := s.NewID()
	p, err := s.fromInput(ctx, orgID, id, in)
	if err != nil {
		return nil, err
	}
	key, cert, err := newKeyPair(p.EntityID, s.now())
	if err != nil {
		return nil, err
	}
	p.certDER = cert.Raw
	p.CertificatePEM = certificatePEM(cert.Raw)
	if p.keyEnc, err = s.sealKey(ctx, orgID, id, key); err != nil {
		return nil, err
	}
	err = s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO saml_providers
			(id, organization_id, name, entity_id, signing_cert, signing_key_enc,
			 idp_entity_id, idp_sso_url, idp_certificates, metadata_url, metadata_fetched_at,
			 email_attribute, name_attribute, groups_attribute, allowed_domains,
			 jit_provisioning, default_role_id, enabled, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NULLIF($17,''),$18,$19)`,
			p.ID, orgID, p.Name, p.EntityID, p.certDER, p.keyEnc,
			p.IDPEntityID, p.IDPSSOURL, p.IDPCertificates, p.MetadataURL, p.MetadataFetchedAt,
			p.EmailAttribute, p.NameAttribute, p.GroupsAttribute, p.AllowedDomains,
			p.JITProvisioning, p.DefaultRoleID, p.Enabled, actorID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Update replaces a provider's configuration. The key pair is left alone:
// the certificate is registered with the identity provider, and replacing
// it on every edit would break every sign-in until someone re-uploaded
// it. Rotate is the deliberate way to replace it.
func (s *Service) Update(ctx context.Context, orgID, id string, in Input) (*Provider, error) {
	p, err := s.fromInput(ctx, orgID, id, in)
	if err != nil {
		return nil, err
	}
	err = s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE saml_providers SET
			name=$3, entity_id=$4, idp_entity_id=$5, idp_sso_url=$6, idp_certificates=$7,
			metadata_url=$8, metadata_fetched_at=$9, email_attribute=$10, name_attribute=$11,
			groups_attribute=$12, allowed_domains=$13, jit_provisioning=$14,
			default_role_id=NULLIF($15,''), enabled=$16, updated_at = now()
			WHERE id = $1 AND organization_id = $2`,
			id, orgID, p.Name, p.EntityID, p.IDPEntityID, p.IDPSSOURL, p.IDPCertificates,
			p.MetadataURL, p.MetadataFetchedAt, p.EmailAttribute, p.NameAttribute,
			p.GroupsAttribute, p.AllowedDomains, p.JITProvisioning, p.DefaultRoleID, p.Enabled)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Report the certificate that is actually in use, not a new one.
	stored, err := s.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	return stored, nil
}

// Rotate replaces the signing key pair. The new certificate has to be
// given to the identity provider before anything we sign with it will be
// accepted, so this is a separate, deliberate step.
func (s *Service) Rotate(ctx context.Context, orgID, id string) (*Provider, error) {
	p, err := s.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	key, cert, err := newKeyPair(p.EntityID, s.now())
	if err != nil {
		return nil, err
	}
	enc, err := s.sealKey(ctx, orgID, id, key)
	if err != nil {
		return nil, err
	}
	err = s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE saml_providers SET signing_cert=$3, signing_key_enc=$4,
			updated_at = now() WHERE id = $1 AND organization_id = $2`, id, orgID, cert.Raw, enc)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	p.certDER, p.keyEnc = cert.Raw, enc
	p.CertificatePEM = certificatePEM(cert.Raw)
	return p, nil
}

// Delete removes a provider. The identities it created stay, so the
// people keep their accounts and their history.
func (s *Service) Delete(ctx context.Context, orgID, id string) error {
	return s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM saml_providers WHERE id = $1 AND organization_id = $2`, id, orgID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

const providerColumns = `id, organization_id, name, entity_id, signing_cert, idp_entity_id, idp_sso_url,
	idp_certificates, metadata_url, metadata_fetched_at, email_attribute, name_attribute, groups_attribute,
	allowed_domains, jit_provisioning, COALESCE(default_role_id,''), enabled`

func scanProvider(rows pgx.Row, p *Provider) error {
	return rows.Scan(&p.ID, &p.OrgID, &p.Name, &p.EntityID, &p.certDER, &p.IDPEntityID, &p.IDPSSOURL,
		&p.IDPCertificates, &p.MetadataURL, &p.MetadataFetchedAt, &p.EmailAttribute, &p.NameAttribute,
		&p.GroupsAttribute, &p.AllowedDomains, &p.JITProvisioning, &p.DefaultRoleID, &p.Enabled)
}

// List returns an organisation's providers. The sealed key never leaves
// the database on this path.
func (s *Service) List(ctx context.Context, orgID string) ([]Provider, error) {
	out := []Provider{}
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+providerColumns+
			` FROM saml_providers WHERE organization_id = $1 ORDER BY name`, orgID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p Provider
			if err := scanProvider(rows, &p); err != nil {
				return err
			}
			p.CertificatePEM = certificatePEM(p.certDER)
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// Get returns one provider of an organisation.
func (s *Service) Get(ctx context.Context, orgID, id string) (*Provider, error) {
	var p Provider
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		return scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+
			` FROM saml_providers WHERE id = $1 AND organization_id = $2`, id, orgID), &p)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.CertificatePEM = certificatePEM(p.certDER)
	return &p, nil
}

// Listings names the enabled providers for the sign-in page, which runs
// before anyone has said who they are.
func (s *Service) Listings(ctx context.Context) ([]SignInOption, error) {
	out := []SignInOption{}
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, name, organization_name FROM auth_saml_provider_list()`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var l SignInOption
			if err := rows.Scan(&l.ID, &l.Name, &l.Org); err != nil {
				return err
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	return out, err
}

// load reads a provider without a tenant: an assertion arrives with a
// provider id in the URL and no session.
func (s *Service) load(ctx context.Context, id string) (*Provider, error) {
	var p Provider
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, organization_id, name, entity_id, signing_cert, signing_key_enc,
			idp_entity_id, idp_sso_url, idp_certificates, metadata_url, metadata_fetched_at, email_attribute,
			name_attribute, groups_attribute, allowed_domains, jit_provisioning,
			COALESCE(default_role_id,''), enabled FROM auth_saml_provider($1)`, id).
			Scan(&p.ID, &p.OrgID, &p.Name, &p.EntityID, &p.certDER, &p.keyEnc,
				&p.IDPEntityID, &p.IDPSSOURL, &p.IDPCertificates, &p.MetadataURL, &p.MetadataFetchedAt,
				&p.EmailAttribute, &p.NameAttribute, &p.GroupsAttribute, &p.AllowedDomains,
				&p.JITProvisioning, &p.DefaultRoleID, &p.Enabled)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.CertificatePEM = certificatePEM(p.certDER)
	return &p, nil
}

// fromInput validates what an administrator sent and resolves the
// identity provider's metadata into the columns we store.
func (s *Service) fromInput(ctx context.Context, orgID, id string, in Input) (*Provider, error) {
	p := &Provider{
		ID: id, OrgID: orgID, Name: strings.TrimSpace(in.Name),
		EntityID:        strings.TrimSpace(in.EntityID),
		MetadataURL:     strings.TrimSpace(in.MetadataURL),
		EmailAttribute:  strings.TrimSpace(in.EmailAttribute),
		NameAttribute:   strings.TrimSpace(in.NameAttribute),
		GroupsAttribute: strings.TrimSpace(in.GroupsAttribute),
		AllowedDomains:  lowerAll(in.AllowedDomains),
		JITProvisioning: in.JITProvisioning,
		DefaultRoleID:   in.DefaultRoleID,
		Enabled:         in.Enabled,
	}
	if p.Name == "" {
		p.Name = "SAML single sign-on"
	}
	if p.EntityID == "" {
		p.EntityID = s.MetadataURL(id)
	}
	doc, err := s.resolveMetadata(ctx, in)
	if err != nil {
		return nil, err
	}
	p.IDPEntityID, p.IDPSSOURL, p.IDPCertificates = doc.entityID, doc.ssoURL, doc.certificates
	if p.MetadataURL != "" {
		fetched := s.now().UTC()
		p.MetadataFetchedAt = &fetched
	}
	return p, nil
}

// resolveMetadata turns whichever form of metadata was supplied into the
// three things a sign-in needs from it.
func (s *Service) resolveMetadata(ctx context.Context, in Input) (*idpMetadata, error) {
	xmlText := strings.TrimSpace(in.MetadataXML)
	metaURL := strings.TrimSpace(in.MetadataURL)
	switch {
	case xmlText != "":
		return parseIDPMetadata([]byte(xmlText))
	case metaURL != "":
		return s.fetchIDPMetadata(ctx, metaURL)
	default:
		return nil, fmt.Errorf("%w: give either the provider's metadata URL or paste its metadata XML",
			ErrMetadata)
	}
}

func (s *Service) sealKey(ctx context.Context, orgID, id string, key []byte) ([]byte, error) {
	return s.Sealer.Seal(ctx, secrets.ScopeOrg(orgID), key,
		secrets.AAD{Table: "saml_providers", Column: "signing_key_enc", RowID: id, OrgID: orgID})
}

func (s *Service) openKey(ctx context.Context, p *Provider) ([]byte, error) {
	if len(p.keyEnc) == 0 {
		return nil, fmt.Errorf("%w: it has no signing key", ErrNotConfigured)
	}
	return s.Sealer.Open(ctx, p.keyEnc,
		secrets.AAD{Table: "saml_providers", Column: "signing_key_enc", RowID: p.ID, OrgID: p.OrgID})
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
