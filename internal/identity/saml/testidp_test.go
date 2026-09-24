package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	crewjam "github.com/crewjam/saml"
)

// A real identity provider, run in the test process with a key the test
// makes. Everything these tests assert about is a property of a signed
// XML document, and a document built by something other than a SAML
// implementation would be proof of nothing.

const (
	gatewayBase = "https://gateway.example"
	providerID  = "idp_test"
	idpBase     = "https://idp.example"
)

type spProviderFunc func(*http.Request, string) (*crewjam.EntityDescriptor, error)

func (f spProviderFunc) GetServiceProvider(r *http.Request, id string) (*crewjam.EntityDescriptor, error) {
	return f(r, id)
}

// harness is one configured federation: our service provider on one side,
// an identity provider we control on the other.
type harness struct {
	t        *testing.T
	provider *Provider
	verifier *verifier
	idp      *crewjam.IdentityProvider
	acsURL   string
	// requestID is the authentication request the assertions answer.
	requestID string
	authnURL  string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	idpKey, idpCert := selfSigned(t, idpBase)
	h := &harness{t: t, acsURL: gatewayBase + "/api/v1/auth/saml/" + providerID + "/acs"}

	metadataURL := mustURL(t, idpBase+"/metadata")
	ssoURL := mustURL(t, idpBase+"/sso")
	h.idp = &crewjam.IdentityProvider{
		Key: idpKey, Certificate: idpCert,
		MetadataURL: *metadataURL, SSOURL: *ssoURL,
		SignatureMethod: signatureMethod,
		// The identity provider is told about us by the metadata our own
		// service provider publishes, minus the encryption key: these
		// tests are about what a signature protects, and an encrypted
		// assertion would hide the bytes under test.
		ServiceProviderProvider: spProviderFunc(func(*http.Request, string) (*crewjam.EntityDescriptor, error) {
			return signingOnly(h.verifier.sp.Metadata()), nil
		}),
	}

	entityID := gatewayBase + "/api/v1/auth/saml/" + providerID + "/metadata"
	h.provider = &Provider{
		ID: providerID, OrgID: "org_test", Name: "Test provider",
		EntityID:        entityID,
		IDPEntityID:     metadataURL.String(),
		IDPSSOURL:       ssoURL.String(),
		IDPCertificates: []string{base64.StdEncoding.EncodeToString(idpCert.Raw)},
		JITProvisioning: true, Enabled: true,
	}
	pkcs8, spCert, err := newKeyPair(entityID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseMaterial(pkcs8, spCert.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.verifier, err = newVerifier(h.provider, m.key, m.cert, *mustURL(t, h.acsURL), *mustURL(t, entityID)); err != nil {
		t.Fatal(err)
	}

	// Start a sign-in the way the service does, so the assertions below
	// answer a request that really exists.
	req, err := h.verifier.sp.MakeAuthenticationRequest(
		ssoURL.String(), crewjam.HTTPRedirectBinding, crewjam.HTTPPostBinding)
	if err != nil {
		t.Fatal(err)
	}
	u, err := req.Redirect("", h.verifier.sp)
	if err != nil {
		t.Fatal(err)
	}
	h.requestID, h.authnURL = req.ID, u.String()
	return h
}

// assertion is the assertion the identity provider would issue for a
// correct sign-in. Each test mutates the one field it is about.
func (h *harness) assertion(now time.Time) *crewjam.Assertion {
	return &crewjam.Assertion{
		ID:           fmt.Sprintf("id-assertion-%d", now.UnixNano()),
		IssueInstant: now,
		Version:      "2.0",
		Issuer: crewjam.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  h.provider.IDPEntityID,
		},
		Subject: &crewjam.Subject{
			NameID: &crewjam.NameID{
				Format:          string(crewjam.EmailAddressNameIDFormat),
				NameQualifier:   h.provider.IDPEntityID,
				SPNameQualifier: h.provider.EntityID,
				Value:           "amara@example.com",
			},
			SubjectConfirmations: []crewjam.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &crewjam.SubjectConfirmationData{
					InResponseTo: h.requestID,
					NotOnOrAfter: now.Add(time.Hour),
					Recipient:    h.acsURL,
				},
			}},
		},
		Conditions: &crewjam.Conditions{
			NotBefore:    now.Add(-time.Minute),
			NotOnOrAfter: now.Add(time.Hour),
			AudienceRestrictions: []crewjam.AudienceRestriction{
				{Audience: crewjam.Audience{Value: h.provider.EntityID}},
			},
		},
		AuthnStatements: []crewjam.AuthnStatement{{
			AuthnInstant: now,
			SessionIndex: "session-1",
			AuthnContext: crewjam.AuthnContext{
				AuthnContextClassRef: &crewjam.AuthnContextClassRef{
					Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				},
			},
		}},
		AttributeStatements: []crewjam.AttributeStatement{{
			Attributes: []crewjam.Attribute{
				attribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
					"amara@example.com"),
				attribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "Amara Okafor"),
				attribute("http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
					"platform-engineering", "on-call"),
			},
		}},
	}
}

// respond signs an assertion into a response, exactly as the identity
// provider would, and returns the base64 a browser would post to us.
func (h *harness) respond(a *crewjam.Assertion) string {
	h.t.Helper()
	req, err := crewjam.NewIdpAuthnRequest(h.idp, httptest.NewRequest(http.MethodGet, h.authnURL, nil))
	if err != nil {
		h.t.Fatal(err)
	}
	if err := req.Validate(); err != nil {
		h.t.Fatal(err)
	}
	req.Assertion = a
	if err := req.MakeResponse(); err != nil {
		h.t.Fatal(err)
	}
	form, err := req.PostBinding()
	if err != nil {
		h.t.Fatal(err)
	}
	return form.SAMLResponse
}

func attribute(name string, values ...string) crewjam.Attribute {
	attr := crewjam.Attribute{Name: name, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"}
	for _, v := range values {
		attr.Values = append(attr.Values, crewjam.AttributeValue{Type: "xs:string", Value: v})
	}
	return attr
}

// signingOnly drops the encryption key from our metadata.
func signingOnly(md *crewjam.EntityDescriptor) *crewjam.EntityDescriptor {
	for i := range md.SPSSODescriptors {
		kept := make([]crewjam.KeyDescriptor, 0, len(md.SPSSODescriptors[i].KeyDescriptors))
		for _, kd := range md.SPSSODescriptors[i].KeyDescriptors {
			if kd.Use != "encryption" {
				kept = append(kept, kd)
			}
		}
		md.SPSSODescriptors[i].KeyDescriptors = kept
	}
	return md
}

// edit rewrites the signed document without re-signing it, which is what
// someone modifying an assertion in the browser can do.
func edit(t *testing.T, encoded string, fn func(string) string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString([]byte(fn(string(raw))))
}

// stripSignatures removes every signature element, leaving a document
// that says all the right things and is vouched for by nobody.
func stripSignatures(doc string) string {
	for {
		open := strings.Index(doc, "<ds:Signature")
		if open < 0 {
			return doc
		}
		close := strings.Index(doc[open:], "</ds:Signature>")
		if close < 0 {
			return doc
		}
		doc = doc[:open] + doc[open+close+len("</ds:Signature>"):]
	}
}

func selfSigned(t *testing.T, commonName string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
