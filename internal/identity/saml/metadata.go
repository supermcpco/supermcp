package saml

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	crewjam "github.com/crewjam/saml"
)

// metadataLimit bounds what we will read from a metadata URL. Federation
// metadata for one provider is a few kilobytes; an aggregate for a whole
// federation is much larger and is not what belongs here.
const metadataLimit = 2 << 20

// idpMetadata is the three things a sign-in needs from an identity
// provider's metadata document.
type idpMetadata struct {
	entityID string
	ssoURL   string
	// certificates are base64 DER, in the order the document listed them,
	// so a provider part-way through a certificate rollover still
	// verifies against whichever half it signed with.
	certificates []string
}

// fetchIDPMetadata reads a metadata document from a URL. The client is
// the guarded one, so the URL cannot be pointed at an internal address.
func (s *Service) fetchIDPMetadata(ctx context.Context, rawURL string) (*idpMetadata, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%w: %q is not a URL", ErrMetadata, rawURL)
	}
	if u.Scheme != "https" && !loopback(u.Hostname()) {
		return nil, fmt.Errorf("%w: the metadata URL must be https", ErrMetadata)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml;q=0.9, */*;q=0.1")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMetadata, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, metadataLimit))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%w: the provider answered %s", ErrMetadata, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, metadataLimit))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMetadata, err)
	}
	return parseIDPMetadata(body)
}

// Probe reads a metadata document without saving anything, so a mistake
// shows up on the configuration screen rather than during someone's first
// sign-in. Either form is accepted, as in Input.
func (s *Service) Probe(ctx context.Context, in Input) (map[string]any, error) {
	doc, err := s.resolveMetadata(ctx, in)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"idpEntityId":  doc.entityID,
		"idpSsoUrl":    doc.ssoURL,
		"certificates": len(doc.certificates),
	}, nil
}

// parseIDPMetadata pulls the identity provider's role out of a metadata
// document. A federation aggregate is accepted too: the first entity
// that describes an identity provider is the one meant.
func parseIDPMetadata(body []byte) (*idpMetadata, error) {
	entity, err := unmarshalEntity(body)
	if err != nil {
		return nil, err
	}
	out := &idpMetadata{entityID: strings.TrimSpace(entity.EntityID)}
	if out.entityID == "" {
		return nil, fmt.Errorf("%w: it names no entity id", ErrMetadata)
	}
	for _, desc := range entity.IDPSSODescriptors {
		for _, kd := range desc.KeyDescriptors {
			// A descriptor with no use is good for signing as well as
			// encryption, which is what the metadata specification says.
			if kd.Use != "" && kd.Use != "signing" {
				continue
			}
			for _, c := range kd.KeyInfo.X509Data.X509Certificates {
				if cleaned := cleanCertificate(c.Data); cleaned != "" {
					out.certificates = append(out.certificates, cleaned)
				}
			}
		}
		for _, svc := range desc.SingleSignOnServices {
			// Redirect is the binding we send authentication requests
			// with, so it is the one worth recording; POST is taken only
			// if the provider publishes nothing else.
			if svc.Binding == crewjam.HTTPRedirectBinding && svc.Location != "" {
				out.ssoURL = svc.Location
			}
			if out.ssoURL == "" && svc.Binding == crewjam.HTTPPostBinding {
				out.ssoURL = svc.Location
			}
		}
	}
	if out.ssoURL == "" {
		return nil, fmt.Errorf("%w: it publishes no sign-on endpoint, so there is nowhere to send people",
			ErrMetadata)
	}
	if len(out.certificates) == 0 {
		return nil, fmt.Errorf("%w: it publishes no signing certificate, so nothing could vouch for an "+
			"assertion from this provider", ErrMetadata)
	}
	return out, nil
}

// unmarshalEntity accepts a single EntityDescriptor or an aggregate.
func unmarshalEntity(body []byte) (*crewjam.EntityDescriptor, error) {
	var entity crewjam.EntityDescriptor
	err := xml.Unmarshal(body, &entity)
	if err == nil {
		return &entity, nil
	}
	var entities crewjam.EntitiesDescriptor
	if aggErr := xml.Unmarshal(body, &entities); aggErr != nil {
		return nil, fmt.Errorf("%w: it is not a SAML metadata document: %w", ErrMetadata, err)
	}
	for i := range entities.EntityDescriptors {
		if len(entities.EntityDescriptors[i].IDPSSODescriptors) > 0 {
			return &entities.EntityDescriptors[i], nil
		}
	}
	return nil, fmt.Errorf("%w: none of the entities in it is an identity provider", ErrMetadata)
}

// cleanCertificate strips the whitespace a metadata document wraps
// base64 with, and refuses anything that is not base64 at all.
func cleanCertificate(data string) string {
	var b strings.Builder
	for _, r := range data {
		switch r {
		case ' ', '\t', '\n', '\r':
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		return ""
	}
	if _, err := base64.StdEncoding.DecodeString(out); err != nil {
		return ""
	}
	return out
}

func loopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// Metadata renders the service provider metadata document an
// administrator uploads to their identity provider.
func (s *Service) Metadata(ctx context.Context, id string) ([]byte, error) {
	p, err := s.load(ctx, id)
	if err != nil {
		return nil, err
	}
	m, err := s.materialFor(ctx, p)
	if err != nil {
		return nil, err
	}
	sp, err := s.serviceProvider(p, m)
	if err != nil {
		return nil, err
	}
	doc, err := xml.MarshalIndent(sp.Metadata(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), doc...), nil
}

// materialFor unseals and parses a provider's key pair.
func (s *Service) materialFor(ctx context.Context, p *Provider) (*material, error) {
	key, err := s.openKey(ctx, p)
	if err != nil {
		return nil, err
	}
	return parseMaterial(key, p.certDER)
}
