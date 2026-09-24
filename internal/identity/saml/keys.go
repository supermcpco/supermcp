package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"time"

	crewjam "github.com/crewjam/saml"
)

// signatureMethod is what we sign authentication requests with. The URI
// is spelled out rather than taken from the XML signature library so that
// library stays an indirect dependency; SHA-1 variants are not offered,
// and every identity provider in use accepts SHA-256.
const signatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

// keyBits is the size of the service provider's signing key. 2048 is what
// identity providers uniformly accept; several still refuse anything
// larger in their metadata upload forms.
const keyBits = 2048

// certificateLifetime is how long the self-signed certificate in our
// metadata is valid. It is long because replacing it means an
// administrator re-uploading it at the identity provider, and short
// enough that a forgotten federation eventually announces itself.
const certificateLifetime = 5 * 365 * 24 * time.Hour

// newKeyPair generates the service provider's signing key and the
// self-signed certificate that carries it. The certificate is not a
// trust statement, it is a container: in SAML the identity provider is
// told this exact certificate out of band, and compares it byte for byte.
func newKeyPair(entityID string, now time.Time) (pkcs8 []byte, cert *x509.Certificate, err error) {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate a signing key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate a certificate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: entityID},
		NotBefore:             now.Add(-time.Hour).UTC(),
		NotAfter:              now.Add(certificateLifetime).UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create the certificate: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	pkcs8, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pkcs8, parsed, nil
}

// certificatePEM renders a stored certificate for an administrator to
// paste into their identity provider.
func certificatePEM(der []byte) string {
	if len(der) == 0 {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// material is a provider's key pair, unsealed and parsed.
type material struct {
	key  crypto.Signer
	cert *x509.Certificate
}

func parseMaterial(pkcs8, certDER []byte) (*material, error) {
	if len(certDER) == 0 {
		return nil, fmt.Errorf("%w: it has no certificate", ErrNotConfigured)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("%w: its certificate could not be read: %w", ErrNotConfigured, err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("%w: its signing key could not be read: %w", ErrNotConfigured, err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: its signing key cannot sign", ErrNotConfigured)
	}
	return &material{key: signer, cert: cert}, nil
}

// endpoints are the two URLs of ours that appear in the protocol: where
// an assertion is posted, and where our metadata is served.
func (s *Service) endpoints(id string) (acs, meta url.URL, err error) {
	a, err := url.Parse(s.ACSURL(id))
	if err != nil {
		return acs, meta, err
	}
	m, err := url.Parse(s.MetadataURL(id))
	if err != nil {
		return acs, meta, err
	}
	return *a, *m, nil
}

// serviceProvider assembles the library's view of us for one provider.
func (s *Service) serviceProvider(p *Provider, m *material) (*crewjam.ServiceProvider, error) {
	acs, meta, err := s.endpoints(p.ID)
	if err != nil {
		return nil, err
	}
	v, err := newVerifier(p, m.key, m.cert, acs, meta)
	if err != nil {
		return nil, err
	}
	return v.sp, nil
}

// setClockSkew widens or narrows the window either side of an assertion's
// validity period. The library keeps these as package variables, so this
// is process-wide; see the note on New.
func setClockSkew(d time.Duration) {
	if d <= 0 {
		return
	}
	crewjam.MaxClockSkew = d
	// The issue delay is the other half of the same tolerance: how stale
	// an assertion may be when it reaches us. Left at the library's 90
	// seconds it, not the skew setting, becomes the limit.
	if crewjam.MaxIssueDelay < d {
		crewjam.MaxIssueDelay = d
	}
}
