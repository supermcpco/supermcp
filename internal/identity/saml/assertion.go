package saml

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	crewjam "github.com/crewjam/saml"
)

// Everything in this file works on values rather than rows, so the rules
// that decide whether an assertion is acceptable can be exercised without
// a database behind them. What reaches here has come off the wire; what
// leaves has been verified.

// Claims are what a verified assertion says about the person.
type Claims struct {
	// AssertionID and NotOnOrAfter are what replay protection records:
	// the id that may be spent once, and the moment after which spending
	// it again would fail the validity check anyway.
	AssertionID  string
	NotOnOrAfter time.Time

	Subject string
	Email   string
	Name    string
	Groups  []string
	// MultiFactor is true when the identity provider said it checked more
	// than one factor. We issue no factor of our own, so this is the only
	// evidence a policy requiring one can read.
	MultiFactor bool
}

// verifier holds everything needed to check an assertion for one
// provider. It is built once per request from a Provider and its key.
type verifier struct {
	sp      *crewjam.ServiceProvider
	acsURL  url.URL
	mapping attributeMapping
}

type attributeMapping struct {
	email  string
	name   string
	groups string
}

// newVerifier assembles the crewjam service provider for one of our
// providers. The identity provider is described from the columns we
// store rather than from a metadata document kept on disk: the two
// things a signature check needs are the issuer's entity id and its
// certificates, and both are columns.
func newVerifier(p *Provider, key crypto.Signer, cert *x509.Certificate, acs, metadata url.URL) (*verifier, error) {
	certs := make([]crewjam.X509Certificate, 0, len(p.IDPCertificates))
	for _, c := range p.IDPCertificates {
		certs = append(certs, crewjam.X509Certificate{Data: c})
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: this provider has no identity provider certificate stored, so nothing "+
			"can vouch for an assertion; load the provider's metadata again", ErrNotConfigured)
	}
	idp := &crewjam.EntityDescriptor{
		EntityID: p.IDPEntityID,
		IDPSSODescriptors: []crewjam.IDPSSODescriptor{{
			SSODescriptor: crewjam.SSODescriptor{
				RoleDescriptor: crewjam.RoleDescriptor{
					KeyDescriptors: []crewjam.KeyDescriptor{{
						Use:     "signing",
						KeyInfo: crewjam.KeyInfo{X509Data: crewjam.X509Data{X509Certificates: certs}},
					}},
				},
			},
			SingleSignOnServices: []crewjam.Endpoint{
				{Binding: crewjam.HTTPRedirectBinding, Location: p.IDPSSOURL},
				{Binding: crewjam.HTTPPostBinding, Location: p.IDPSSOURL},
			},
		}},
	}
	return &verifier{
		sp: &crewjam.ServiceProvider{
			EntityID:    p.EntityID,
			Key:         key,
			Certificate: cert,
			MetadataURL: metadata,
			AcsURL:      acs,
			IDPMetadata: idp,
			// An unsolicited assertion is one we cannot tie to a sign-in
			// anyone here started, so it is refused: InResponseTo must name
			// a request of ours.
			AllowIDPInitiated: false,
			AuthnNameIDFormat: crewjam.EmailAddressNameIDFormat,
			SignatureMethod:   signatureMethod,
		},
		acsURL: acs,
		mapping: attributeMapping{
			email:  p.EmailAttribute,
			name:   p.NameAttribute,
			groups: p.GroupsAttribute,
		},
	}, nil
}

// verify checks one base64 SAMLResponse against one in-flight request and
// returns what it says. The library enforces the parts of the SAML
// profile that are not ours to decide: a signature on the response or on
// the assertion, the issuer, the destination, the validity window with
// clock skew, and the audience restriction against our entity id.
func (v *verifier) verify(encoded, requestID string) (*Claims, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("%w: the response was not valid base64", ErrAssertionInvalid)
	}
	assertion, err := v.sp.ParseXMLResponse(raw, []string{requestID}, v.acsURL)
	if err != nil {
		// The library's Error() is deliberately uninformative; the cause
		// is on PrivateErr and belongs in the log, not in a redirect.
		var detail *crewjam.InvalidResponseError
		if errors.As(err, &detail) && detail.PrivateErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrAssertionInvalid, detail.PrivateErr)
		}
		return nil, fmt.Errorf("%w: %w", ErrAssertionInvalid, err)
	}
	return v.claims(assertion)
}

// claims reads the person out of a verified assertion.
func (v *verifier) claims(a *crewjam.Assertion) (*Claims, error) {
	if a.Subject == nil || a.Subject.NameID == nil || a.Subject.NameID.Value == "" {
		return nil, fmt.Errorf("%w: the assertion named no subject", ErrAssertionInvalid)
	}
	c := &Claims{
		AssertionID: a.ID,
		Subject:     a.Subject.NameID.Value,
		Name:        firstAttribute(a, v.mapping.name, nameAttributes),
		Groups:      allAttributes(a, v.mapping.groups, groupAttributes),
		MultiFactor: multiFactor(a),
	}
	if a.Conditions != nil {
		c.NotOnOrAfter = a.Conditions.NotOnOrAfter
	}
	c.Email = strings.ToLower(strings.TrimSpace(firstAttribute(a, v.mapping.email, emailAttributes)))
	if c.Email == "" && isEmailNameID(a.Subject.NameID) {
		// A NameID in email format is an address the provider asserted,
		// which is exactly what an email attribute would have been.
		c.Email = strings.ToLower(strings.TrimSpace(a.Subject.NameID.Value))
	}
	if c.Email == "" {
		return nil, ErrEmailMissing
	}
	if a.ID == "" {
		return nil, fmt.Errorf("%w: the assertion carried no id, so it cannot be spent once", ErrAssertionInvalid)
	}
	return c, nil
}

func isEmailNameID(id *crewjam.NameID) bool {
	return id.Format == "" || id.Format == string(crewjam.EmailAddressNameIDFormat) ||
		id.Format == string(crewjam.UnspecifiedNameIDFormat)
}

// The attribute names identity providers actually send when nobody has
// configured anything. The claim URIs are what Entra ID and AD FS emit;
// the urn:oid forms are what Shibboleth and most academic providers emit;
// the bare words are what Okta, Google and JumpCloud emit by default.
var (
	emailAttributes = []string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		"urn:oid:0.9.2342.19200300.100.1.3",
		"urn:oid:1.2.840.113549.1.9.1",
		"email", "emailaddress", "mail", "user.email",
	}
	nameAttributes = []string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname",
		"urn:oid:2.16.840.1.113730.3.1.241",
		"urn:oid:2.5.4.3",
		"displayname", "name", "cn", "commonname",
	}
	groupAttributes = []string{
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
		"http://schemas.xmlsoap.org/claims/Group",
		"urn:oid:1.3.6.1.4.1.5923.1.5.1.1",
		"groups", "group", "memberof", "role", "roles",
	}
	// amrAttributes name the claim carrying the authentication methods.
	// Entra ID sends it as a claim URI; others copy the OpenID Connect
	// spelling.
	amrAttributes = []string{
		"http://schemas.microsoft.com/claims/authnmethodsreferences",
		"amr", "authnmethodsreferences",
	}
)

// firstAttribute returns the first value of the configured attribute, or
// of the first well-known name that is present.
func firstAttribute(a *crewjam.Assertion, configured string, fallbacks []string) string {
	vals := allAttributes(a, configured, fallbacks)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// allAttributes returns every value of the configured attribute. A
// configured name is used on its own: an administrator who names an
// attribute means that one, and silently falling back to another would
// hand out roles from a claim they did not choose.
func allAttributes(a *crewjam.Assertion, configured string, fallbacks []string) []string {
	if configured != "" {
		return attributeValues(a, configured)
	}
	for _, name := range fallbacks {
		if vals := attributeValues(a, name); len(vals) > 0 {
			return vals
		}
	}
	return nil
}

// attributeValues matches on Name or FriendlyName, ignoring case, because
// the same attribute is spelled "emailAddress", "emailaddress" and
// "EmailAddress" by three providers we have to work with.
func attributeValues(a *crewjam.Assertion, name string) []string {
	want := strings.ToLower(name)
	var out []string
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if strings.ToLower(attr.Name) != want && strings.ToLower(attr.FriendlyName) != want {
				continue
			}
			for _, v := range attr.Values {
				if s := strings.TrimSpace(v.Value); s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// multiFactorContexts are the authentication context classes that mean
// more than one factor was checked. The SAML classes are from the
// authentication context specification; the Microsoft URI is what Entra
// ID sends when a conditional access policy demanded a second factor.
var multiFactorContexts = map[string]bool{
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication": true,
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract":   true,
	"urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI":              true,
	"urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken":             true,
	"http://schemas.microsoft.com/claims/multipleauthn":                true,
}

// multiFactorAMR are the authentication method references that mean a
// second factor, in the spelling RFC 8176 fixed. "mfa" is the one that
// says so outright; the others are factors nobody holds as their only
// one, so a provider that lists them checked a password as well.
var multiFactorAMR = map[string]bool{
	"mfa": true, "otp": true, "hwk": true, "sms": true, "tel": true,
}

// multiFactor reports whether the assertion says a second factor was
// checked, from either the authentication context or an amr attribute.
func multiFactor(a *crewjam.Assertion) bool {
	for _, stmt := range a.AuthnStatements {
		if ref := stmt.AuthnContext.AuthnContextClassRef; ref != nil && multiFactorContexts[ref.Value] {
			return true
		}
	}
	for _, name := range amrAttributes {
		for _, v := range attributeValues(a, name) {
			if multiFactorAMR[strings.ToLower(v)] {
				return true
			}
		}
	}
	return false
}

// responseRequestID reads InResponseTo off an unverified response. It is
// used only to find the sign-in this response claims to answer; the
// signed document is then checked against that same id, so a forged value
// buys nothing but a refusal.
func responseRequestID(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", fmt.Errorf("%w: the response was not valid base64", ErrAssertionInvalid)
	}
	var probe struct {
		XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
		InResponseTo string   `xml:"InResponseTo,attr"`
	}
	if err := xml.Unmarshal(raw, &probe); err != nil {
		return "", fmt.Errorf("%w: the response was not a SAML response document", ErrAssertionInvalid)
	}
	if probe.InResponseTo == "" {
		return "", fmt.Errorf("%w: the response answered no sign-in request; unsolicited assertions are "+
			"not accepted here, so start again from the sign-in page", ErrAssertionInvalid)
	}
	return probe.InResponseTo, nil
}
