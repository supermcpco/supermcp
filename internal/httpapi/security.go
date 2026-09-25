package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/identity"
)

// securityRoutes cover what a person manages about their own account, and
// what an administrator sets for the organisation.
func (d Deps) securityRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "change-password", Method: http.MethodPost,
		Path: "/api/v1/auth/password", Summary: "Change your own password", Tags: []string{"auth"},
		Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			Body struct {
				CurrentPassword string `json:"currentPassword,omitempty"`
				NewPassword     string `json:"newPassword" minLength:"8"`
			}
		}) (*struct {
			Body struct {
				Changed bool `json:"changed"`
			}
		}, error) {
			p, ok := authz.From(ctx)
			if !ok || p.AuthMethod != "session" {
				return nil, huma.Error401Unauthorized("sign in again to change your password")
			}
			// A password session proves itself here with the current
			// password. A single sign-on session has nothing to prove it
			// with, and the account may have no password at all, so
			// setting one from a stale session would hand whoever holds
			// the cookie a way in that outlives it.
			if p.SignIn.Method != "password" {
				if err := d.checkFresh(ctx, p, "", authz.Resource{OrgID: p.OrgID}); err != nil {
					return nil, err
				}
			}
			if err := d.Identity.ChangePassword(ctx, p.ID, p.OrgID, in.Body.CurrentPassword, in.Body.NewPassword); err != nil {
				d.emit(ctx, audit.Event{Category: audit.CategoryAuth, Action: "password.change",
					Outcome: audit.Failure, Meta: map[string]any{"reason": err.Error()}})
				return nil, humaErr(err)
			}
			d.emit(ctx, audit.Event{Category: audit.CategoryAuth, Action: "password.change", Outcome: audit.Success})
			// Every other session belonged to the old password.
			if err := d.Identity.RevokeOtherSessions(ctx, p.ID, p.SessionID, "password changed"); err != nil {
				d.Log.Warn("could not end the other sessions after a password change", "user", p.ID, "err", err)
			}
			out := &struct {
				Body struct {
					Changed bool `json:"changed"`
				}
			}{}
			out.Body.Changed = true
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "get-password-policy", Method: http.MethodGet,
		Path: "/api/v1/org/password-policy", Summary: "Read the organisation's password policy",
		Tags: []string{"identity"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body identity.PasswordPolicy }, error) {
			p, ok := authz.From(ctx)
			if !ok || p.OrgID == "" {
				return nil, huma.Error401Unauthorized("authentication required")
			}
			policy, err := d.Identity.LoadPolicy(ctx, p.OrgID)
			if err != nil {
				return nil, err
			}
			return &struct{ Body identity.PasswordPolicy }{Body: policy}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "set-password-policy", Method: http.MethodPut,
		Path: "/api/v1/org/password-policy", Summary: "Set the organisation's password policy",
		Tags: []string{"identity"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct{ Body identity.PasswordPolicy }) (*struct{ Body identity.PasswordPolicy }, error) {
			p, err := d.requireFresh(ctx, authz.OrgSettingsManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			before, _ := d.Identity.LoadPolicy(ctx, p.OrgID)
			policy, err := d.Identity.SetPolicy(ctx, p.OrgID, in.Body)
			if err != nil {
				d.adminFailed(ctx, "password_policy.update", "organization", p.OrgID, err)
				return nil, humaErr(err)
			}
			d.admin(ctx, "password_policy.update", "organization", p.OrgID, "", audit.Changes(before, policy))
			return &struct{ Body identity.PasswordPolicy }{Body: policy}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "list-sessions", Method: http.MethodGet,
		Path: "/api/v1/auth/sessions", Summary: "List your signed-in devices", Tags: []string{"auth"},
		Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct {
			Body struct {
				Sessions []identity.SessionInfo `json:"sessions"`
				Current  string                 `json:"current"`
			}
		}, error) {
			p, ok := authz.From(ctx)
			if !ok || p.OrgID == "" {
				return nil, huma.Error401Unauthorized("authentication required")
			}
			list, err := d.Identity.Sessions(ctx, p.OrgID, p.ID)
			if err != nil {
				return nil, err
			}
			out := &struct {
				Body struct {
					Sessions []identity.SessionInfo `json:"sessions"`
					Current  string                 `json:"current"`
				}
			}{}
			out.Body.Sessions, out.Body.Current = list, p.SessionID
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "revoke-session", Method: http.MethodDelete,
		Path: "/api/v1/auth/sessions/{id}", Summary: "End one of your sessions", Tags: []string{"auth"},
		Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct{}, error) {
			p, ok := authz.From(ctx)
			if !ok || p.OrgID == "" {
				return nil, huma.Error401Unauthorized("authentication required")
			}
			// A session id is a bearer credential, so ownership is checked
			// against the list rather than by trusting the id in the path.
			list, err := d.Identity.Sessions(ctx, p.OrgID, p.ID)
			if err != nil {
				return nil, err
			}
			for _, s := range list {
				if s.ID == in.ID {
					if err := d.Identity.RevokeSession(ctx, in.ID, "ended by its owner"); err != nil {
						return nil, err
					}
					d.emit(ctx, audit.Event{Category: audit.CategoryAuth, Action: "session.revoke",
						Outcome: audit.Success, TargetKind: "session", TargetID: in.ID})
					return nil, nil //nolint:nilnil // huma's no-content shape
				}
			}
			return nil, huma.Error404NotFound("no such session")
		})

	d.serviceAccountRoutes(api)
}

type serviceAccountInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	ServerID    string   `json:"serverId,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

func (d Deps) serviceAccountRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "list-service-accounts", Method: http.MethodGet,
		Path: "/api/v1/service-accounts", Summary: "List the organisation's service accounts",
		Tags: []string{"identity"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct {
			Body struct {
				Accounts []identity.ServiceAccount `json:"accounts"`
				TokenURL string                    `json:"tokenUrl"`
			}
		}, error) {
			p, err := d.require(ctx, authz.ServiceAccounts, authz.Resource{})
			if err != nil {
				return nil, err
			}
			list, err := d.Identity.ListServiceAccounts(ctx, p.OrgID)
			if err != nil {
				return nil, err
			}
			out := &struct {
				Body struct {
					Accounts []identity.ServiceAccount `json:"accounts"`
					TokenURL string                    `json:"tokenUrl"`
				}
			}{}
			out.Body.Accounts = list
			out.Body.TokenURL = d.Config.PublicURL.String() + "/oauth/token"
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "create-service-account", Method: http.MethodPost,
		Path: "/api/v1/service-accounts", Summary: "Create a service account", Tags: []string{"identity"},
		Security: sessionSecurity, DefaultStatus: http.StatusCreated},
		func(ctx context.Context, in *struct{ Body serviceAccountInput }) (*struct {
			Body identity.ServiceAccount
		}, error) {
			p, err := d.requireFresh(ctx, authz.ServiceAccounts, authz.Resource{})
			if err != nil {
				return nil, err
			}
			sa, err := d.Identity.CreateServiceAccount(ctx, p.OrgID, p.ID, identity.ServiceAccountInput{
				Name: in.Body.Name, Description: in.Body.Description, ServerID: in.Body.ServerID, Scopes: in.Body.Scopes})
			if err != nil {
				d.adminFailed(ctx, "service_account.create", "service_account", "", err)
				return nil, humaErr(err)
			}
			// The one-time secret is dropped before the record is built.
			recorded := *sa
			recorded.Secret = ""
			d.admin(ctx, "service_account.create", "service_account", sa.ID, sa.Name, audit.Created(recorded))
			return &struct{ Body identity.ServiceAccount }{Body: *sa}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "rotate-service-account-secret", Method: http.MethodPost,
		Path: "/api/v1/service-accounts/{id}/rotate", Summary: "Issue a new secret for a service account",
		Tags: []string{"identity"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct {
			Body struct {
				Secret string `json:"secret"`
			}
		}, error) {
			p, err := d.requireFresh(ctx, authz.ServiceAccounts, authz.Resource{})
			if err != nil {
				return nil, err
			}
			secret, err := d.Identity.RotateServiceAccountSecret(ctx, p.OrgID, in.ID)
			if err != nil {
				d.adminFailed(ctx, "service_account.rotate_secret", "service_account", in.ID, err)
				return nil, humaErr(err)
			}
			d.emit(ctx, audit.Event{Category: audit.CategorySecrets, Action: "service_account.rotate_secret",
				Outcome: audit.Success, TargetKind: "service_account", TargetID: in.ID})
			out := &struct {
				Body struct {
					Secret string `json:"secret"`
				}
			}{}
			out.Body.Secret = secret
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "set-service-account-disabled", Method: http.MethodPost,
		Path: "/api/v1/service-accounts/{id}/disabled", Summary: "Turn a service account off or on",
		Tags: []string{"identity"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID   string `path:"id"`
			Body struct {
				Disabled bool `json:"disabled"`
			}
		}) (*struct {
			Body struct {
				Disabled bool `json:"disabled"`
			}
		}, error) {
			p, err := d.requireFresh(ctx, authz.ServiceAccounts, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if err := d.Identity.SetServiceAccountDisabled(ctx, p.OrgID, in.ID, in.Body.Disabled); err != nil {
				d.adminFailed(ctx, "service_account.update", "service_account", in.ID, err)
				return nil, humaErr(err)
			}
			d.admin(ctx, "service_account.update", "service_account", in.ID, "",
				&audit.Diff{After: map[string]any{"disabled": in.Body.Disabled}})
			out := &struct {
				Body struct {
					Disabled bool `json:"disabled"`
				}
			}{}
			out.Body.Disabled = in.Body.Disabled
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "delete-service-account", Method: http.MethodDelete,
		Path: "/api/v1/service-accounts/{id}", Summary: "Delete a service account", Tags: []string{"identity"},
		Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct{}, error) {
			p, err := d.requireFresh(ctx, authz.ServiceAccounts, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if err := d.Identity.DeleteServiceAccount(ctx, p.OrgID, in.ID); err != nil {
				d.adminFailed(ctx, "service_account.delete", "service_account", in.ID, err)
				return nil, humaErr(err)
			}
			d.admin(ctx, "service_account.delete", "service_account", in.ID, "", nil)
			return nil, nil //nolint:nilnil // huma's no-content shape
		})
}
