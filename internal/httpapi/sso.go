package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/identity/sso"
)

// ssoBrowserRoutes are the two plain redirects a sign-in needs. They are
// not part of the JSON API: a browser follows them, and the provider
// redirects back to one of them.
func (d Deps) ssoBrowserRoutes(r chi.Router) {
	r.Get("/auth/sso/{id}/start", d.ssoStart)
	r.Get("/auth/sso/callback", d.ssoCallback)
}

func (d Deps) ssoStart(w http.ResponseWriter, r *http.Request) {
	// The browser carries a secret through the sign-in, so the code can
	// only be exchanged by the browser that asked for it.
	binding, err := newFlowSecret()
	if err != nil {
		d.ssoFailed(w, r, err)
		return
	}
	url, err := d.SSO.Begin(r.Context(), chi.URLParam(r, "id"), r.URL.Query().Get("next"), binding, reauthReplaces(r))
	if err != nil {
		d.ssoFailed(w, r, err)
		return
	}
	w.Header().Add("Set-Cookie", d.flowCookie(ssoFlowCookie, binding, int(ssoFlowTTL.Seconds()), false))
	//nolint:gosec // the URL comes from the provider's own metadata
	http.Redirect(w, r, url, http.StatusFound)
}

func (d Deps) ssoCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		d.ssoFailed(w, r, errors.New(firstNonEmpty(q.Get("error_description"), e)))
		return
	}
	binding := ""
	if c, cerr := r.Cookie(d.flowCookieName(ssoFlowCookie)); cerr == nil {
		binding = c.Value
	}
	res, err := d.SSO.Callback(r.Context(), q.Get("state"), q.Get("code"), binding)
	// The sign-in is over either way, so the cookie goes whatever happened.
	w.Header().Add("Set-Cookie", d.flowCookie(ssoFlowCookie, "", 0, false))
	if err != nil {
		d.ssoFailed(w, r, err)
		return
	}
	// A second factor is recorded only when the verified ID token met the
	// provider's rule, for a re-authentication as for a first sign-in, so
	// a password at the provider does not earn the session's MFA flag or
	// the mfa its tokens claim. The audit event carries what the token said, which is
	// what an administrator writing the rule needs to see.
	meta := map[string]any{"method": "sso", "provider": res.ProviderName, "groups": res.Groups, "mfa": res.MultiFactor}
	if res.AuthMethods != nil {
		meta["amr"] = res.AuthMethods
	}
	if res.ACR != "" {
		meta["acr"] = res.ACR
	}
	d.finishProviderSignIn(w, r, providerSignIn{
		UserID: res.UserID, OrgID: res.OrgID, Email: res.Email, ProviderID: res.ProviderID,
		ProviderName: res.ProviderName, Method: "sso", At: res.AuthTime, Replaces: res.Replaces,
		Verified: res.MultiFactor, Methods: res.AuthMethods, Next: res.RedirectAfter, Meta: meta,
	}, func(err error) { d.ssoFailed(w, r, err) })
}

// ssoFailed sends the person back to the sign-in page with something they
// can act on, and logs the detail. A provider's message may name an
// internal address, so it does not go in the URL.
func (d Deps) ssoFailed(w http.ResponseWriter, r *http.Request, err error) {
	d.Log.Warn("single sign-on failed", "err", err, "path", r.URL.Path, "req_id", middleware.GetReqID(r.Context()))
	ip, _ := r.Context().Value(ipKey).(string)
	d.emit(r.Context(), audit.Event{Category: audit.CategoryAuth, Action: "session.create", Outcome: audit.Failure,
		IP: ip, UserAgent: r.UserAgent(), Meta: errorMeta(r.Context(), map[string]any{"method": "sso"}, "reason", err)})
	reason := "sso_failed"
	switch {
	case errors.Is(err, sso.ErrDomainRefused):
		reason = "domain_not_allowed"
	case errors.Is(err, sso.ErrNoAccount):
		reason = "no_account"
	case errors.Is(err, sso.ErrStateInvalid):
		reason = "expired"
	case errors.Is(err, sso.ErrEmailMissing):
		reason = "no_verified_email"
	case errors.Is(err, sso.ErrDisabled), errors.Is(err, sso.ErrNotFound):
		reason = "unavailable"
	}
	http.Redirect(w, r, "/login?sso_error="+reason, http.StatusFound)
}

// --- administration --------------------------------------------------------

type idpDTO struct {
	sso.Provider
	// SecretSet says whether a client secret is stored, without saying what
	// it is. The value is write-only for its whole life.
	SecretSet bool `json:"clientSecretSet"`
}

// idpRestoreDTO is a restored provider, and says what a restore does not
// put back. It repeats idpDTO's field rather than embedding it: the schema
// generator does not see through an unexported embedded type.
type idpRestoreDTO struct {
	sso.Provider
	SecretSet        bool `json:"clientSecretSet"`
	ClientSecretKept bool `json:"clientSecretKept" doc:"True when the restore kept the client secret stored now, which it does unless the request supplied a new one. The history never holds a client secret."`
}

// idpRestoreInput names the revision to restore, and optionally the
// client secret to restore it with. A secret is needed when the revision
// points the provider at another issuer or host; otherwise the stored one
// is kept.
type idpRestoreInput struct {
	ID       string `path:"id"`
	Revision int    `path:"revision" minimum:"1"`
	Body     *struct {
		ClientSecret string `json:"clientSecret,omitempty" doc:"The client secret to use from now on. Needed when the revision points the provider at a different issuer or host than it uses now; otherwise leave it out to keep the stored one."`
	} `required:"false"`
}

type idpInput struct {
	Name                  string   `json:"name,omitempty"`
	Preset                string   `json:"preset" enum:"entra,google,okta,auth0,github,generic"`
	Issuer                string   `json:"issuer,omitempty"`
	ClientID              string   `json:"clientId"`
	ClientSecret          string   `json:"clientSecret,omitempty"`
	Scopes                []string `json:"scopes,omitempty"`
	AllowedDomains        []string `json:"allowedDomains,omitempty"`
	JITProvisioning       bool     `json:"jitProvisioning,omitempty"`
	DefaultRoleID         string   `json:"defaultRoleId,omitempty"`
	GroupsClaim           string   `json:"groupsClaim,omitempty"`
	Enabled               bool     `json:"enabled,omitempty"`
	AuthorizationEndpoint string   `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string   `json:"tokenEndpoint,omitempty"`
	UserinfoEndpoint      string   `json:"userinfoEndpoint,omitempty"`
	JWKSURI               string   `json:"jwksUri,omitempty"`
	// MFA is a pointer so that leaving it out keeps what is stored, which
	// a client written before the rule existed does.
	MFA *sso.MFARule `json:"mfa,omitempty" doc:"Which answers from the provider count as a second factor. Left out, a new OpenID Connect provider gets amr [mfa, otp, hwk, sc] and an existing one keeps its rule; both lists empty counts nothing. Refused for GitHub, which issues no ID token."`
}

func (in idpInput) toInput() sso.Input {
	return sso.Input{
		Name: in.Name, Preset: in.Preset, Issuer: in.Issuer, ClientID: in.ClientID, ClientSecret: in.ClientSecret,
		Scopes: in.Scopes, AllowedDomains: in.AllowedDomains, JITProvisioning: in.JITProvisioning,
		DefaultRoleID: in.DefaultRoleID, GroupsClaim: in.GroupsClaim, Enabled: in.Enabled,
		AuthorizationEndpoint: in.AuthorizationEndpoint, TokenEndpoint: in.TokenEndpoint,
		UserinfoEndpoint: in.UserinfoEndpoint, JWKSURI: in.JWKSURI, MFA: in.MFA,
	}
}

// ssoUnavailable reports the one case where these routes cannot work: an
// instance built without the service. The routes are still registered, so
// the generated OpenAPI document and the client describe them either way.
func (d Deps) ssoUnavailable() error {
	if d.SSO == nil {
		return huma.Error503ServiceUnavailable("single sign-on is not configured on this instance")
	}
	return nil
}

func (d Deps) ssoRoutes(api huma.API) {
	// The sign-in page is anonymous: it needs the names to put on buttons.
	huma.Register(api, huma.Operation{OperationID: "list-sso-providers", Method: http.MethodGet,
		Path: "/api/v1/auth/sso-providers", Summary: "List the sign-in providers offered on this instance",
		Tags: []string{"auth"}},
		func(ctx context.Context, _ *struct{}) (*struct {
			Body struct {
				Providers []sso.Listing `json:"providers"`
			}
		}, error) {
			out := &struct {
				Body struct {
					Providers []sso.Listing `json:"providers"`
				}
			}{}
			out.Body.Providers = []sso.Listing{}
			if d.SSO == nil {
				return out, nil // nothing to offer, which is not an error
			}
			list, err := d.SSO.Listings(ctx)
			if err != nil {
				return nil, err
			}
			if list != nil {
				out.Body.Providers = list
			}
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "list-idps", Method: http.MethodGet, Path: "/api/v1/idps",
		Summary: "List the organisation's identity providers", Tags: []string{"identity"}},
		func(ctx context.Context, _ *struct{}) (*struct {
			Body struct {
				Providers []idpDTO         `json:"providers"`
				Presets   []map[string]any `json:"presets"`
				Redirect  string           `json:"redirectUri"`
			}
		}, error) {
			if err := d.ssoUnavailable(); err != nil {
				return nil, err
			}
			p, err := d.require(ctx, authz.IdpManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			list, err := d.SSO.List(ctx, p.OrgID)
			if err != nil {
				return nil, err
			}
			out := &struct {
				Body struct {
					Providers []idpDTO         `json:"providers"`
					Presets   []map[string]any `json:"presets"`
					Redirect  string           `json:"redirectUri"`
				}
			}{}
			for _, prov := range list {
				out.Body.Providers = append(out.Body.Providers, idpDTO{Provider: prov, SecretSet: true})
			}
			out.Body.Presets = sso.Presets()
			out.Body.Redirect = d.SSO.RedirectURI()
			if out.Body.Providers == nil {
				out.Body.Providers = []idpDTO{}
			}
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "create-idp", Method: http.MethodPost, Path: "/api/v1/idps",
		Summary: "Add an identity provider", Tags: []string{"identity"}, DefaultStatus: http.StatusCreated},
		func(ctx context.Context, in *struct{ Body idpInput }) (*struct{ Body idpDTO }, error) {
			if err := d.ssoUnavailable(); err != nil {
				return nil, err
			}
			p, err := d.requireFresh(ctx, authz.IdpManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			prov, err := d.SSO.Create(ctx, p.OrgID, p.ID, in.Body.toInput())
			if err != nil {
				d.adminFailed(ctx, "idp.create", "identity_provider", "", err)
				return nil, ssoErr(err)
			}
			d.admin(ctx, "idp.create", "identity_provider", prov.ID, prov.Name, audit.Created(prov))
			return &struct{ Body idpDTO }{Body: idpDTO{Provider: *prov, SecretSet: in.Body.ClientSecret != ""}}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "update-idp", Method: http.MethodPut, Path: "/api/v1/idps/{id}",
		Summary: "Change an identity provider", Tags: []string{"identity"}},
		func(ctx context.Context, in *struct {
			ID   string `path:"id"`
			Body idpInput
		}) (*struct{ Body idpDTO }, error) {
			if err := d.ssoUnavailable(); err != nil {
				return nil, err
			}
			p, err := d.requireFresh(ctx, authz.IdpManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			prov, before, err := d.SSO.Update(ctx, p.OrgID, in.ID, p.ID, in.Body.toInput())
			if err != nil {
				d.adminFailed(ctx, "idp.update", "identity_provider", in.ID, err)
				return nil, ssoErr(err)
			}
			d.admin(ctx, "idp.update", "identity_provider", prov.ID, prov.Name,
				audit.Changes(sso.SnapshotOf(before), sso.SnapshotOf(prov)))
			return &struct{ Body idpDTO }{Body: idpDTO{Provider: *prov, SecretSet: true}}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "delete-idp", Method: http.MethodDelete, Path: "/api/v1/idps/{id}",
		Summary: "Remove an identity provider", Tags: []string{"identity"}, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct{}, error) {
			if err := d.ssoUnavailable(); err != nil {
				return nil, err
			}
			p, err := d.requireFresh(ctx, authz.IdpManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if err := d.SSO.Delete(ctx, p.OrgID, in.ID, p.ID); err != nil {
				d.adminFailed(ctx, "idp.delete", "identity_provider", in.ID, err)
				return nil, humaErr(err)
			}
			d.admin(ctx, "idp.delete", "identity_provider", in.ID, "", nil)
			return nil, nil //nolint:nilnil // huma's no-content shape
		})

	// A restore is an update with no client secret in it, which is how an
	// update keeps the stored one. The history never held the secret: a
	// secret an earlier version used may have been revoked at the provider
	// since, and a sealed copy in the history would be one more place a
	// secret lives that rotating it does not reach.
	huma.Register(api, huma.Operation{OperationID: "idps-revisions-restore", Method: http.MethodPost,
		Path:    "/api/v1/idps/{id}/revisions/{revision}/restore",
		Summary: "Put an identity provider back the way an earlier revision found it",
		Description: "Needs revisions:rollback and idp:manage, and a browser session must have signed in within " +
			"the fresh-auth window. The client secret is not restored; the one stored now is kept, unless the " +
			"revision points the provider at a different issuer or host, which is refused with 422 unless the " +
			"request supplies a new clientSecret. A deleted provider cannot be restored: its client secret went with it.",
		Tags: []string{"identity"}, Security: sessionSecurity},
		func(ctx context.Context, restore *idpRestoreInput) (*struct{ Body idpRestoreDTO }, error) {
			if err := d.ssoUnavailable(); err != nil {
				return nil, err
			}
			in := &revisionGetInput{ID: restore.ID, Revision: restore.Revision}
			p, snapshot, err := d.snapshotToRestore(ctx, idpRevisions, in)
			if err != nil {
				return nil, err
			}
			var snap sso.Snapshot
			if err := snapInto(snapshot, "", &snap); err != nil {
				return nil, err
			}
			input := snap.Input()
			if restore.Body != nil {
				input.ClientSecret = restore.Body.ClientSecret
			}
			prov, before, err := d.SSO.Update(ctx, p.OrgID, in.ID, p.ID, input)
			if err != nil {
				d.restoreFailed(ctx, idpRevisions, in, err)
				if errors.Is(err, sso.ErrNotFound) {
					return nil, huma.Error404NotFound("this identity provider has been deleted; a deleted provider " +
						"cannot be restored from its history, because its client secret went with it")
				}
				return nil, ssoErr(err)
			}
			d.admin(ctx, "idp.update", "identity_provider", prov.ID, prov.Name,
				audit.Changes(sso.SnapshotOf(before), sso.SnapshotOf(prov)))
			d.restored(ctx, idpRevisions, in, prov.Name)
			return &struct{ Body idpRestoreDTO }{Body: idpRestoreDTO{Provider: *prov, SecretSet: true,
				ClientSecretKept: input.ClientSecret == ""}}, nil
		})

	// Checking an issuer before saving turns a failed sign-in later into a
	// message on the configuration screen now.
	huma.Register(api, huma.Operation{OperationID: "probe-idp", Method: http.MethodPost, Path: "/api/v1/idps/probe",
		Summary: "Read a provider's metadata without saving anything", Tags: []string{"identity"}},
		func(ctx context.Context, in *struct {
			Body struct {
				Issuer string `json:"issuer"`
			}
		}) (*struct {
			Body map[string]string
		}, error) {
			if err := d.ssoUnavailable(); err != nil {
				return nil, err
			}
			if _, err := d.require(ctx, authz.IdpManage, authz.Resource{}); err != nil {
				return nil, err
			}
			doc, err := d.SSO.Discover(ctx, strings.TrimSpace(in.Body.Issuer))
			if err != nil {
				return nil, huma.Error400BadRequest(err.Error())
			}
			return &struct{ Body map[string]string }{Body: doc}, nil
		})
}

// ssoErr maps the service's errors onto statuses; a change that would
// send the stored secret somewhere new is one the caller can fix by
// supplying a secret, and so is a configuration that is not valid.
func ssoErr(err error) error {
	if errors.Is(err, sso.ErrSecretRequired) {
		return huma.Error422UnprocessableEntity(err.Error())
	}
	if errors.Is(err, sso.ErrInvalid) {
		return huma.Error400BadRequest(err.Error())
	}
	return humaErr(err)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
