package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/identity"
)

// --- names -----------------------------------------------------------------

// A person changes their own display name; an administrator renames the
// organisation. Both answer with what the sidebar reads, so the client
// can show the new name without asking again.

// renameInput is the body of both renames. The rules (1 to 120
// characters once trimmed, no control characters) are identity's
// CleanName, so there is one place that decides them.
type renameInput struct {
	Body struct {
		Name string `json:"name" maxLength:"512" doc:"The new name: 1 to 120 characters once leading and trailing space is trimmed, with no control or bidirectional formatting characters"`
	}
}

type orgOutput struct {
	Body orgDTO
}

func (d Deps) profileRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "me-update", Method: http.MethodPatch, Path: "/api/v1/me",
		Summary: "Change your own display name", Tags: []string{"auth"}, Security: sessionSecurity,
		Description: "Only a browser session may call it: an API key, an OAuth access token or a service account " +
			"acts for a person but is not them, and gets 403. A person an identity provider provisions through SCIM, " +
			"in any workspace, gets 409: the provider owns the name. Answers with the session, as " +
			"GET /api/v1/auth/session does. No session ends."},
		func(ctx context.Context, in *renameInput) (*sessionOutput, error) {
			p, ok := authz.From(ctx)
			if !ok {
				return nil, huma.Error401Unauthorized("authentication required")
			}
			if p.AuthMethod != "session" {
				refused := huma.Error403Forbidden("only a signed-in person can change their own name")
				d.accountUpdate(ctx, p, audit.Denied, errorMeta(ctx, map[string]any{"authMethod": p.AuthMethod}, "reason", refused))
				return nil, refused
			}
			if p.OrgID == "" {
				// The name is changed under a workspace's row-level
				// security, and there is none to change it under.
				return nil, huma.Error409Conflict("select a workspace first")
			}
			before, after, err := d.Identity.RenameUser(ctx, p.OrgID, p.ID, in.Body.Name)
			if err != nil {
				outcome := audit.Failure
				if errors.Is(err, identity.ErrNameManaged) {
					outcome = audit.Denied
				}
				d.accountUpdate(ctx, p, outcome, errorMeta(ctx, nil, "error", err))
				return nil, humaErr(err)
			}
			// The name belongs to the person, not to a workspace: every
			// workspace they are in shows it, so each one's trail says it
			// changed.
			orgIDs := []string{p.OrgID}
			orgs, err := d.Identity.Orgs(ctx, p.ID)
			if err != nil {
				d.Log.Warn("could not list the workspaces to record a rename in", "user", p.ID, "err", err,
					"req_id", middleware.GetReqID(ctx))
			}
			for _, o := range orgs {
				if o.ID != p.OrgID {
					orgIDs = append(orgIDs, o.ID)
				}
			}
			for _, orgID := range orgIDs {
				d.emit(ctx, audit.Event{OrgID: orgID, Category: audit.CategoryAuth, Action: "account.update",
					Outcome: audit.Success, TargetKind: "user", TargetID: p.ID, TargetDisplay: p.Email,
					Diff: nameDiff(before, after)})
			}
			return d.sessionBodyFor(ctx, p)
		})

	huma.Register(api, huma.Operation{OperationID: "org-update", Method: http.MethodPatch, Path: "/api/v1/org",
		Summary: "Rename the organisation", Tags: []string{"identity"}, Security: sessionSecurity,
		Description: "Needs org:update. Changes the name only; the slug stays."},
		func(ctx context.Context, in *renameInput) (*orgOutput, error) {
			p, err := d.require(ctx, authz.OrgUpdate, authz.Resource{})
			if err != nil {
				return nil, err
			}
			before, after, err := d.Identity.RenameOrg(ctx, p.OrgID, in.Body.Name)
			if err != nil {
				d.adminFailed(ctx, "org.update", "organization", p.OrgID, err)
				return nil, humaErr(err)
			}
			d.admin(ctx, "org.update", "organization", after.ID, after.Name, nameDiff(before.Name, after.Name))
			return &orgOutput{Body: orgDTO{ID: after.ID, Slug: after.Slug, Name: after.Name}}, nil
		})
}

// nameDiff records a rename. It is built by hand rather than with
// audit.Changes so that renaming to the same name still says what the
// name was.
func nameDiff(before, after string) *audit.Diff {
	return &audit.Diff{Before: map[string]any{"name": before}, After: map[string]any{"name": after}}
}

// accountUpdate records a rename of yourself that did not happen, in the
// selected workspace.
func (d Deps) accountUpdate(ctx context.Context, p *authz.Principal, outcome string, meta map[string]any) {
	d.emit(ctx, audit.Event{Category: audit.CategoryAuth, Action: "account.update", Outcome: outcome,
		TargetKind: "user", TargetID: p.ID, TargetDisplay: p.Email, Meta: meta})
}
