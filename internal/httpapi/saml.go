package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/identity/saml"
)

// samlAPI is the shared wiring plus the SAML service. The service is
// handed to the registrars below rather than read off Deps, so this
// package does not decide how the process holds it; everything else a
// handler needs comes from the embedded Deps as usual.
type samlAPI struct {
	Deps
	svc *saml.Service
}

// SAMLRoutes registers the administration API. It is registered whether
// or not the service exists, so the generated OpenAPI document and the
// client describe these operations either way.
//
// This and SAMLBrowserRoutes are exported because they are the seam the
// process wires SAML in at, and the service reaches them as an argument
// rather than as a field on Deps.
func (d Deps) SAMLRoutes(api huma.API, svc *saml.Service) {
	samlAPI{Deps: d, svc: svc}.register(api)
}

// SAMLBrowserRoutes are the three endpoints the SAML protocol needs. They
// are not part of the JSON API: a browser and an identity provider follow
// them, and two of the three answer with a redirect or with XML.
//
// The assertion consumer is a POST that arrives from the identity
// provider's own origin, so it is a cross-site form submission by
// definition. It carries no ambient credential: the signed assertion is
// the whole of what authenticates it.
func (d Deps) SAMLBrowserRoutes(r chi.Router, svc *saml.Service) {
	s := samlAPI{Deps: d, svc: svc}
	r.Get("/api/v1/auth/saml/{id}/login", s.start)
	r.Get("/api/v1/auth/saml/{id}/metadata", s.metadata)
	r.Post("/api/v1/auth/saml/{id}/acs", s.acs)
}

func (s samlAPI) start(w http.ResponseWriter, r *http.Request) {
	// The browser that starts a sign-in carries a secret through it, so
	// that the assertion can only finish the sign-in it answers, in the
	// browser that asked. Without it, somebody signs in as themselves and
	// posts the answer into another person's browser.
	binding, err := newFlowSecret()
	if err != nil {
		s.failed(w, r, err)
		return
	}
	url, err := s.svc.Begin(r.Context(), chi.URLParam(r, "id"), r.URL.Query().Get("next"), binding)
	if err != nil {
		s.failed(w, r, err)
		return
	}
	w.Header().Add("Set-Cookie", s.flowCookie(samlFlowCookie, binding, int(samlFlowTTL.Seconds()), true))
	//nolint:gosec // the URL comes from the provider's own metadata
	http.Redirect(w, r, url, http.StatusFound)
}

// metadata publishes what an administrator uploads to their identity
// provider. It is public on purpose: it contains our entity id, our
// consumer URL and our certificate, all of which the other side needs
// before anyone can sign in, and none of which is a secret.
func (s samlAPI) metadata(w http.ResponseWriter, r *http.Request) {
	doc, err := s.svc.Metadata(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		s.Log.Warn("could not render SAML metadata", "err", err, "path", r.URL.Path)
		status := http.StatusInternalServerError
		if errors.Is(err, saml.ErrNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The document is rendered by the SAML service from this instance's
	// own entity id, endpoints and certificate. Nothing in it came from
	// the request, and it is served as XML rather than as a page.
	_, _ = w.Write(doc) //nolint:gosec // our own metadata, not request data
}

func (s samlAPI) acs(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.failed(w, r, err)
		return
	}
	binding := ""
	if c, cerr := r.Cookie(s.flowCookieName(samlFlowCookie)); cerr == nil {
		binding = c.Value
	}
	res, err := s.svc.Consume(r.Context(), chi.URLParam(r, "id"), r.PostFormValue("SAMLResponse"), binding)
	// The sign-in is over either way, so the cookie goes whatever happened.
	w.Header().Add("Set-Cookie", s.flowCookie(samlFlowCookie, "", 0, true))
	if err != nil {
		s.failed(w, r, err)
		return
	}
	ip, _ := r.Context().Value(ipKey).(string)
	sess, err := s.Identity.CreateSession(r.Context(), res.UserID, res.OrgID, "saml", res.ProviderID, ip, r.UserAgent())
	if err != nil {
		s.failed(w, r, err)
		return
	}
	s.emit(r.Context(), audit.Event{OrgID: res.OrgID, Category: audit.CategoryAuth, Action: "session.create",
		Outcome: audit.Success, ActorKind: "user", ActorID: res.UserID, ActorDisplay: res.Email,
		SessionID: sess.ID, IP: ip, UserAgent: r.UserAgent(),
		Meta: map[string]any{"method": "saml", "provider": res.ProviderName, "groups": res.Groups,
			"mfa": res.MultiFactor}})
	// Unlike the OpenID Connect path, this is conditional. A SAML
	// assertion states which authentication context the provider used, so
	// recording a second factor it never mentioned would let a policy
	// that requires one be satisfied by a password.
	if res.MultiFactor {
		if err := s.Identity.MarkVerified(r.Context(), sess.ID); err != nil {
			s.Log.Warn("could not record the provider's verification", "session", sess.ID, "err", err)
		}
	}
	w.Header().Add("Set-Cookie", s.cookieValue(sess.Secret, int(s.Identity.Cfg.SessionAbsolute.Seconds())))
	next := res.RedirectAfter
	if next == "" {
		next = "/"
	}
	//nolint:gosec // safeRedirect in the saml package kept this path local
	http.Redirect(w, r, next, http.StatusFound)
}

// failed sends the person back to the sign-in page with something they
// can act on, and logs the detail. A provider's message may name an
// internal address, so it does not go in the URL.
func (s samlAPI) failed(w http.ResponseWriter, r *http.Request, err error) {
	s.Log.Warn("saml sign-in failed", "err", err, "path", r.URL.Path)
	ip, _ := r.Context().Value(ipKey).(string)
	s.emit(r.Context(), audit.Event{Category: audit.CategoryAuth, Action: "session.create", Outcome: audit.Failure,
		IP: ip, UserAgent: r.UserAgent(), Meta: map[string]any{"method": "saml", "reason": err.Error()}})
	http.Redirect(w, r, "/login?saml_error="+samlReason(err), http.StatusFound)
}

// samlReason is the one word the sign-in page turns into a sentence. The
// detail stays in the log and the audit record.
func samlReason(err error) string {
	switch {
	case errors.Is(err, saml.ErrDomainRefused):
		return "domain_not_allowed"
	case errors.Is(err, saml.ErrNoAccount):
		return "no_account"
	case errors.Is(err, saml.ErrRequestInvalid):
		return "expired"
	case errors.Is(err, saml.ErrReplayed):
		return "already_used"
	case errors.Is(err, saml.ErrEmailMissing):
		return "no_verified_email"
	case errors.Is(err, saml.ErrAssertionInvalid):
		return "assertion_refused"
	case errors.Is(err, saml.ErrDisabled), errors.Is(err, saml.ErrNotFound), errors.Is(err, saml.ErrNotConfigured):
		return "unavailable"
	}
	return "saml_failed"
}

// --- administration --------------------------------------------------------

type samlDTO struct {
	saml.Provider
	// The URLs an administrator has to give their identity provider. They
	// follow from the provider id and this instance's public URL, so they
	// are reported rather than stored.
	ACSURL      string `json:"acsUrl"`
	MetadataURL string `json:"spMetadataUrl"`
	LoginURL    string `json:"loginUrl"`
}

func (s samlAPI) dto(p saml.Provider) samlDTO {
	return samlDTO{Provider: p, ACSURL: s.svc.ACSURL(p.ID),
		MetadataURL: s.svc.MetadataURL(p.ID), LoginURL: s.svc.LoginURL(p.ID)}
}

type samlInput struct {
	Name            string   `json:"name,omitempty"`
	EntityID        string   `json:"entityId,omitempty"`
	MetadataURL     string   `json:"metadataUrl,omitempty"`
	MetadataXML     string   `json:"metadataXml,omitempty"`
	EmailAttribute  string   `json:"emailAttribute,omitempty"`
	NameAttribute   string   `json:"nameAttribute,omitempty"`
	GroupsAttribute string   `json:"groupsAttribute,omitempty"`
	AllowedDomains  []string `json:"allowedDomains,omitempty"`
	JITProvisioning bool     `json:"jitProvisioning,omitempty"`
	DefaultRoleID   string   `json:"defaultRoleId,omitempty"`
	Enabled         bool     `json:"enabled,omitempty"`
}

func (in samlInput) toInput() saml.Input {
	return saml.Input{
		Name: in.Name, EntityID: in.EntityID, MetadataURL: in.MetadataURL, MetadataXML: in.MetadataXML,
		EmailAttribute: in.EmailAttribute, NameAttribute: in.NameAttribute,
		GroupsAttribute: in.GroupsAttribute, AllowedDomains: in.AllowedDomains,
		JITProvisioning: in.JITProvisioning, DefaultRoleID: in.DefaultRoleID, Enabled: in.Enabled,
	}
}

// unavailable reports the one case where these routes cannot work: an
// instance built without the service.
func (s samlAPI) unavailable() error {
	if s.svc == nil {
		return huma.Error503ServiceUnavailable("SAML single sign-on is not configured on this instance")
	}
	return nil
}

// samlErr maps the service's errors onto statuses. Everything an
// administrator can get wrong is a 400 carrying the sentence that says
// what to fix.
func samlErr(err error) error {
	switch {
	case errors.Is(err, saml.ErrNotFound):
		return huma.Error404NotFound(err.Error())
	case errors.Is(err, saml.ErrMetadata), errors.Is(err, saml.ErrNotConfigured):
		return huma.Error400BadRequest(err.Error())
	default:
		return humaErr(err)
	}
}

type samlListBody struct {
	Providers []samlDTO `json:"providers"`
}

type samlSignInBody struct {
	Providers []saml.SignInOption `json:"providers"`
}

type samlProbeBody struct {
	MetadataURL string `json:"metadataUrl,omitempty"`
	MetadataXML string `json:"metadataXml,omitempty"`
}

func (s samlAPI) register(api huma.API) {
	// The sign-in page is anonymous: it needs the names to put on buttons.
	huma.Register(api, huma.Operation{OperationID: "list-saml-sign-in", Method: http.MethodGet,
		Path: "/api/v1/auth/saml-providers", Summary: "List the SAML providers offered on this instance",
		Tags: []string{"auth"}},
		func(ctx context.Context, _ *struct{}) (*struct{ Body samlSignInBody }, error) {
			out := &struct{ Body samlSignInBody }{}
			out.Body.Providers = []saml.SignInOption{}
			if s.svc == nil {
				return out, nil // nothing to offer, which is not an error
			}
			list, err := s.svc.Listings(ctx)
			if err != nil {
				return nil, err
			}
			if list != nil {
				out.Body.Providers = list
			}
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "list-saml-providers", Method: http.MethodGet,
		Path: "/api/v1/saml-providers", Summary: "List the organisation's SAML providers",
		Tags: []string{"identity"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body samlListBody }, error) {
			if err := s.unavailable(); err != nil {
				return nil, err
			}
			p, err := s.require(ctx, authz.IdpManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			list, err := s.svc.List(ctx, p.OrgID)
			if err != nil {
				return nil, err
			}
			out := &struct{ Body samlListBody }{}
			out.Body.Providers = []samlDTO{}
			for _, prov := range list {
				out.Body.Providers = append(out.Body.Providers, s.dto(prov))
			}
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "create-saml-provider", Method: http.MethodPost,
		Path: "/api/v1/saml-providers", Summary: "Add a SAML identity provider",
		Tags: []string{"identity"}, DefaultStatus: http.StatusCreated, Security: sessionSecurity},
		func(ctx context.Context, in *struct{ Body samlInput }) (*struct{ Body samlDTO }, error) {
			if err := s.unavailable(); err != nil {
				return nil, err
			}
			p, err := s.require(ctx, authz.IdpManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			prov, err := s.svc.Create(ctx, p.OrgID, p.ID, in.Body.toInput())
			if err != nil {
				s.adminFailed(ctx, "saml.create", "saml_provider", "", err)
				return nil, samlErr(err)
			}
			s.admin(ctx, "saml.create", "saml_provider", prov.ID, prov.Name, audit.Created(prov))
			return &struct{ Body samlDTO }{Body: s.dto(*prov)}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "update-saml-provider", Method: http.MethodPut,
		Path: "/api/v1/saml-providers/{id}", Summary: "Change a SAML identity provider",
		Tags: []string{"identity"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID   string `path:"id"`
			Body samlInput
		}) (*struct{ Body samlDTO }, error) {
			if err := s.unavailable(); err != nil {
				return nil, err
			}
			p, err := s.require(ctx, authz.IdpManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			prov, err := s.svc.Update(ctx, p.OrgID, in.ID, in.Body.toInput())
			if err != nil {
				s.adminFailed(ctx, "saml.update", "saml_provider", in.ID, err)
				return nil, samlErr(err)
			}
			s.admin(ctx, "saml.update", "saml_provider", prov.ID, prov.Name, audit.Created(prov))
			return &struct{ Body samlDTO }{Body: s.dto(*prov)}, nil
		})

	// Replacing the key pair is its own operation because the new
	// certificate has to reach the identity provider before anything we
	// sign with it is accepted; doing it on every edit would break a
	// working federation without anyone asking for that.
	huma.Register(api, huma.Operation{OperationID: "rotate-saml-key", Method: http.MethodPost,
		Path: "/api/v1/saml-providers/{id}/rotate-key", Summary: "Replace a SAML provider's signing key pair",
		Tags: []string{"identity"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct{ Body samlDTO }, error) {
			if err := s.unavailable(); err != nil {
				return nil, err
			}
			p, err := s.require(ctx, authz.IdpManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			prov, err := s.svc.Rotate(ctx, p.OrgID, in.ID)
			if err != nil {
				s.adminFailed(ctx, "saml.rotate-key", "saml_provider", in.ID, err)
				return nil, samlErr(err)
			}
			s.admin(ctx, "saml.rotate-key", "saml_provider", prov.ID, prov.Name, nil)
			return &struct{ Body samlDTO }{Body: s.dto(*prov)}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "delete-saml-provider", Method: http.MethodDelete,
		Path: "/api/v1/saml-providers/{id}", Summary: "Remove a SAML identity provider",
		Tags: []string{"identity"}, DefaultStatus: http.StatusNoContent, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct{}, error) {
			if err := s.unavailable(); err != nil {
				return nil, err
			}
			p, err := s.require(ctx, authz.IdpManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if err := s.svc.Delete(ctx, p.OrgID, in.ID); err != nil {
				s.adminFailed(ctx, "saml.delete", "saml_provider", in.ID, err)
				return nil, samlErr(err)
			}
			s.admin(ctx, "saml.delete", "saml_provider", in.ID, "", nil)
			return nil, nil //nolint:nilnil // huma's no-content shape
		})

	// Reading the metadata before saving turns a failed sign-in later
	// into a message on the configuration screen now.
	huma.Register(api, huma.Operation{OperationID: "probe-saml-metadata", Method: http.MethodPost,
		Path: "/api/v1/saml-providers/probe", Summary: "Read an identity provider's metadata without saving anything",
		Tags: []string{"identity"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct{ Body samlProbeBody }) (*struct{ Body map[string]any }, error) {
			if err := s.unavailable(); err != nil {
				return nil, err
			}
			if _, err := s.require(ctx, authz.IdpManage, authz.Resource{}); err != nil {
				return nil, err
			}
			doc, err := s.svc.Probe(ctx, saml.Input{
				MetadataURL: in.Body.MetadataURL, MetadataXML: in.Body.MetadataXML})
			if err != nil {
				return nil, huma.Error400BadRequest(err.Error())
			}
			return &struct{ Body map[string]any }{Body: doc}, nil
		})
}
