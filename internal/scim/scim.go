// Package scim serves SCIM 2.0 so an identity provider can create,
// deactivate and group the people who work here.
//
// Provisioning is the half of single sign-on that matters on the way out:
// sign-in alone lets a former employee keep an account that still holds
// role bindings and API keys. A deactivation here revokes every credential
// the person holds, not just their ability to sign in again.
package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/reqid"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// Schema URNs.
const (
	schemaUser          = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup         = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaListResponse  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaError         = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaPatchOp       = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaServiceConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
)

const contentType = "application/scim+json"

// maxPageSize bounds a provider that asks for everything at once.
const maxPageSize = 200

// Service implements the provisioning operations.
type Service struct {
	DB       *tenant.DB
	Identity *identity.Service
	Authz    *authz.Evaluator
	NewID    func() string
	// Audit records provisioning decisions. Who was deprovisioned, and
	// when, is the question asked after someone leaves.
	Audit audit.Sink
	// Log receives the errors a provider is not told about. Nil logs to
	// slog.Default.
	Log *slog.Logger
	now func() time.Time
}

// New builds the service.
func New(db *tenant.DB, id *identity.Service, az *authz.Evaluator, newID func() string) *Service {
	return &Service{DB: db, Identity: id, Authz: az, NewID: newID, now: time.Now}
}

// emit records a provisioning event against the credential that made it.
func (s *Service) emit(ctx context.Context, action, outcome, targetKind, targetID, display string, meta map[string]any) {
	if s.Audit == nil {
		return
	}
	p, _ := authz.From(ctx)
	s.Audit.Emit(ctx, audit.FromPrincipal(audit.Event{
		Category: audit.CategoryAdmin, Action: action, Outcome: outcome,
		TargetKind: targetKind, TargetID: targetID, TargetDisplay: display, Meta: meta,
		RequestID: middleware.GetReqID(ctx),
	}, p))
}

// Routes mounts the SCIM surface. Every route requires a credential with
// the SCIM permission, which in practice is an API key held by the
// identity provider.
func (s *Service) Routes(r chi.Router) {
	r.Route("/scim/v2", func(r chi.Router) {
		r.Use(s.require)
		r.Get("/ServiceProviderConfig", s.serviceProviderConfig)
		r.Get("/ResourceTypes", s.resourceTypes)
		r.Get("/Schemas", s.schemas)

		r.Get("/Users", s.listUsers)
		r.Post("/Users", s.createUser)
		r.Get("/Users/{id}", s.getUser)
		r.Put("/Users/{id}", s.replaceUser)
		r.Patch("/Users/{id}", s.patchUser)
		r.Delete("/Users/{id}", s.deleteUser)

		r.Get("/Groups", s.listGroups)
		r.Post("/Groups", s.createGroup)
		r.Get("/Groups/{id}", s.getGroup)
		r.Put("/Groups/{id}", s.replaceGroup)
		r.Patch("/Groups/{id}", s.patchGroup)
		r.Delete("/Groups/{id}", s.deleteGroup)
	})
}

func (s *Service) require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := authz.From(r.Context())
		if !ok {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if err := s.Authz.Require(r.Context(), authz.ScimManage, authz.Resource{OrgID: p.OrgID}); err != nil {
			if !errors.Is(err, authz.ErrDenied) {
				// The decision could not be made. The provider is still
				// refused, but the cause is the operator's to see.
				s.logger().ErrorContext(r.Context(), "scim authorisation failed",
					"req_id", middleware.GetReqID(r.Context()), "path", r.URL.Path, "err", err)
			}
			writeErr(w, http.StatusForbidden, "this credential may not provision users")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- users -----------------------------------------------------------------

// User is the SCIM representation.
type User struct {
	Schemas    []string   `json:"schemas"`
	ID         string     `json:"id"`
	ExternalID string     `json:"externalId,omitempty"`
	UserName   string     `json:"userName"`
	Name       *scimName  `json:"name,omitempty"`
	Emails     []scimMail `json:"emails,omitempty"`
	// Active is a pointer because an absent field and false mean different
	// things in a PATCH: absent leaves the state alone.
	Active *bool     `json:"active,omitempty"`
	Groups []scimRef `json:"groups,omitempty"`
	Meta   *meta     `json:"meta,omitempty"`
}

type scimName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type scimMail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

type scimRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

type meta struct {
	ResourceType string     `json:"resourceType"`
	Created      *time.Time `json:"created,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
	Location     string     `json:"location,omitempty"`
}

type record struct {
	userID, externalID, userName, email, name string
	active                                    bool
	created, modified                         time.Time
}

func (s *Service) listUsers(w http.ResponseWriter, r *http.Request) {
	orgID := orgOf(r)
	start, count := page(r)
	attr, value := parseFilter(r.URL.Query().Get("filter"))
	if attr != "" && attr != "username" && attr != "externalid" && attr != "active" {
		writeScimErr(w, http.StatusBadRequest, "invalidFilter", "only userName, externalId and active can be filtered")
		return
	}
	var out []record
	var total int
	ctx := tenant.WithOrg(r.Context(), orgID)
	err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT su.user_id, COALESCE(su.external_id,''), su.user_name,
			u.email, u.name, su.active, su.created_at, su.updated_at, count(*) OVER ()
			FROM scim_users su JOIN users u ON u.id = su.user_id
			WHERE su.organization_id = $1
			  AND ($2 = '' OR ($2 = 'username' AND lower(su.user_name) = lower($3))
			                OR ($2 = 'externalid' AND su.external_id = $3)
			                OR ($2 = 'active' AND su.active = ($3 = 'true')))
			ORDER BY su.user_name OFFSET $4 LIMIT $5`, orgID, attr, value, start-1, count)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec record
			if err := rows.Scan(&rec.userID, &rec.externalID, &rec.userName, &rec.email, &rec.name,
				&rec.active, &rec.created, &rec.modified, &total); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	resources := make([]any, 0, len(out))
	for _, rec := range out {
		resources = append(resources, s.userFrom(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas": []string{schemaListResponse}, "totalResults": total,
		"startIndex": start, "itemsPerPage": len(resources), "Resources": resources,
	})
}

func (s *Service) getUser(w http.ResponseWriter, r *http.Request) {
	rec, err := s.loadUser(r.Context(), orgOf(r), chi.URLParam(r, "id"))
	if err != nil {
		s.lookupErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.userFrom(*rec))
}

func (s *Service) createUser(w http.ResponseWriter, r *http.Request) {
	var in User
	if err := decode(r, &in); err != nil {
		writeScimErr(w, http.StatusBadRequest, "invalidSyntax", err.Error())
		return
	}
	email := strings.ToLower(strings.TrimSpace(firstEmail(in)))
	if email == "" {
		writeScimErr(w, http.StatusBadRequest, "invalidValue", "userName or an email address is required")
		return
	}
	orgID := orgOf(r)
	name := in.UserName
	if in.Name != nil && in.Name.Formatted != "" {
		name = in.Name.Formatted
	} else if in.Name != nil {
		name = strings.TrimSpace(in.Name.GivenName + " " + in.Name.FamilyName)
	}
	userID := s.NewID()
	var created string
	ctx := r.Context()
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT auth_scim_upsert_user($1,$2,$3,$4,$5,$6,$7)`,
			orgID, userID, email, name, firstNonEmpty(in.UserName, email), in.ExternalID, activeOrDefault(in)).Scan(&created)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rec, err := s.loadUser(r.Context(), orgID, created)
	if err != nil {
		s.lookupErr(w, r, err)
		return
	}
	s.emit(r.Context(), "scim.user.create", audit.Success, "user", created, email,
		map[string]any{"externalId": in.ExternalID})
	writeJSON(w, http.StatusCreated, s.userFrom(*rec))
}

func (s *Service) replaceUser(w http.ResponseWriter, r *http.Request) {
	var in User
	if err := decode(r, &in); err != nil {
		writeScimErr(w, http.StatusBadRequest, "invalidSyntax", err.Error())
		return
	}
	id := chi.URLParam(r, "id")
	orgID := orgOf(r)
	if _, err := s.loadUser(r.Context(), orgID, id); err != nil {
		s.lookupErr(w, r, err)
		return
	}
	if err := s.setActive(r.Context(), orgID, id, activeOrDefault(in)); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := tenant.WithOrg(r.Context(), orgID)
	err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE scim_users SET user_name = $3, external_id = NULLIF($4,''), updated_at = now()
			WHERE organization_id = $1 AND user_id = $2`, orgID, id, firstNonEmpty(in.UserName, firstEmail(in)), in.ExternalID); err != nil {
			return err
		}
		if in.Name != nil {
			display := firstNonEmpty(in.Name.Formatted, strings.TrimSpace(in.Name.GivenName+" "+in.Name.FamilyName))
			if display != "" {
				if _, err := tx.Exec(ctx, `UPDATE users SET name = $2, updated_at = now() WHERE id = $1`, id, display); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rec, err := s.loadUser(r.Context(), orgID, id)
	if err != nil {
		s.lookupErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.userFrom(*rec))
}

// patchOp is one operation in a PATCH request.
type patchOp struct {
	Schemas    []string `json:"schemas"`
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"Operations"`
}

// patchUser applies the operations a provider actually sends: activate,
// deactivate, and the occasional attribute update.
func (s *Service) patchUser(w http.ResponseWriter, r *http.Request) {
	var in patchOp
	if err := decode(r, &in); err != nil {
		writeScimErr(w, http.StatusBadRequest, "invalidSyntax", err.Error())
		return
	}
	id, orgID := chi.URLParam(r, "id"), orgOf(r)
	if _, err := s.loadUser(r.Context(), orgID, id); err != nil {
		s.lookupErr(w, r, err)
		return
	}
	for _, op := range in.Operations {
		path := strings.ToLower(strings.TrimSpace(op.Path))
		switch {
		case path == "active":
			var active any
			if err := json.Unmarshal(op.Value, &active); err != nil {
				writeScimErr(w, http.StatusBadRequest, "invalidValue", "active must be a boolean")
				return
			}
			if err := s.setActive(r.Context(), orgID, id, truthy(active)); err != nil {
				s.fail(w, r, err)
				return
			}
		case path == "" && len(op.Value) > 0:
			// A pathless replace carries a partial resource.
			var body User
			if err := json.Unmarshal(op.Value, &body); err == nil && body.Active != nil {
				if err := s.setActive(r.Context(), orgID, id, *body.Active); err != nil {
					s.fail(w, r, err)
					return
				}
			}
		}
		// Anything else is accepted and ignored: a provider that syncs a
		// display name it alone owns should not see a 400 for it.
	}
	rec, err := s.loadUser(r.Context(), orgID, id)
	if err != nil {
		s.lookupErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.userFrom(*rec))
}

// deleteUser deactivates rather than erasing: audit records name the
// person, and a deleted row would orphan them.
func (s *Service) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, orgID := chi.URLParam(r, "id"), orgOf(r)
	if _, err := s.loadUser(r.Context(), orgID, id); err != nil {
		s.lookupErr(w, r, err)
		return
	}
	if err := s.setActive(r.Context(), orgID, id, false); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// setActive is where deprovisioning happens: it also ends the sessions and
// revokes the keys and refresh tokens of a person being switched off.
func (s *Service) setActive(ctx context.Context, orgID, userID string, active bool) error {
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE scim_users SET active = $3, updated_at = now()
			WHERE organization_id = $1 AND user_id = $2`, orgID, userID, active); err != nil {
			return err
		}

		var at any
		if !active {
			at = s.now()
		}
		_, err := tx.Exec(ctx, `UPDATE organization_members SET deactivated_at = $3
			WHERE organization_id = $1 AND user_id = $2`, orgID, userID, at)
		return err
	})
	if err != nil {
		return err
	}
	if active {
		s.emit(ctx, "scim.user.activate", audit.Success, "user", userID, "", nil)
		return nil
	}
	// Deactivation is the event that matters most in this package: it is
	// the moment a person stops being able to reach anything.
	revoked, err := s.Identity.RevokeEverything(ctx, orgID, userID, "deprovisioned")
	if err != nil {
		// The handler answers with fail, which logs err under the same
		// request id.
		id := middleware.GetReqID(ctx)
		s.emit(ctx, "scim.user.deactivate", audit.Failure, "user", userID, "",
			map[string]any{"error": reqid.Message(id), "requestId": id})
		return err
	}
	s.emit(ctx, "scim.user.deactivate", audit.Success, "user", userID, "",
		map[string]any{"revoked": "sessions, api keys, refresh tokens", "revokedTokens": revoked})
	return nil
}

func (s *Service) loadUser(ctx context.Context, orgID, userID string) (*record, error) {
	var rec record
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT su.user_id, COALESCE(su.external_id,''), su.user_name, u.email, u.name,
			su.active, su.created_at, su.updated_at
			FROM scim_users su JOIN users u ON u.id = su.user_id
			WHERE su.organization_id = $1 AND su.user_id = $2`, orgID, userID).
			Scan(&rec.userID, &rec.externalID, &rec.userName, &rec.email, &rec.name,
				&rec.active, &rec.created, &rec.modified)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Service) userFrom(rec record) User {
	u := User{
		Schemas: []string{schemaUser}, ID: rec.userID, ExternalID: rec.externalID, UserName: rec.userName,
		Emails: []scimMail{{Value: rec.email, Primary: true, Type: "work"}}, Active: &rec.active,
		Meta: &meta{ResourceType: "User", Created: &rec.created, LastModified: &rec.modified,
			Location: "/scim/v2/Users/" + rec.userID},
	}
	if rec.name != "" {
		u.Name = &scimName{Formatted: rec.name}
	}
	return u
}

// --- groups ----------------------------------------------------------------

// Group is the SCIM representation. Membership of a group grants whatever
// role bindings name that group, which is how a provider's groups turn
// into permissions here.
type Group struct {
	Schemas     []string  `json:"schemas"`
	ID          string    `json:"id"`
	ExternalID  string    `json:"externalId,omitempty"`
	DisplayName string    `json:"displayName"`
	Members     []scimRef `json:"members,omitempty"`
	Meta        *meta     `json:"meta,omitempty"`
}

func (s *Service) listGroups(w http.ResponseWriter, r *http.Request) {
	orgID := orgOf(r)
	start, count := page(r)
	attr, value := parseFilter(r.URL.Query().Get("filter"))
	if attr != "" && attr != "displayname" && attr != "externalid" {
		writeScimErr(w, http.StatusBadRequest, "invalidFilter", "only displayName and externalId can be filtered")
		return
	}
	var ids []string
	var total int
	ctx := tenant.WithOrg(r.Context(), orgID)
	err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, count(*) OVER () FROM scim_groups
			WHERE organization_id = $1
			  AND ($2 = '' OR ($2 = 'displayname' AND lower(display_name) = lower($3))
			                OR ($2 = 'externalid' AND external_id = $3))
			ORDER BY display_name OFFSET $4 LIMIT $5`, orgID, attr, value, start-1, count)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id, &total); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	resources := make([]any, 0, len(ids))
	for _, id := range ids {
		g, err := s.loadGroup(r.Context(), orgID, id)
		if err != nil {
			continue
		}
		resources = append(resources, g)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas": []string{schemaListResponse}, "totalResults": total,
		"startIndex": start, "itemsPerPage": len(resources), "Resources": resources,
	})
}

func (s *Service) getGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.loadGroup(r.Context(), orgOf(r), chi.URLParam(r, "id"))
	if err != nil {
		s.lookupErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Service) createGroup(w http.ResponseWriter, r *http.Request) {
	var in Group
	if err := decode(r, &in); err != nil {
		writeScimErr(w, http.StatusBadRequest, "invalidSyntax", err.Error())
		return
	}
	if strings.TrimSpace(in.DisplayName) == "" {
		writeScimErr(w, http.StatusBadRequest, "invalidValue", "displayName is required")
		return
	}
	orgID, id := orgOf(r), s.NewID()
	ctx := tenant.WithOrg(r.Context(), orgID)
	err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO scim_groups (id, organization_id, display_name, external_id)
			VALUES ($1,$2,$3,NULLIF($4,''))
			ON CONFLICT (organization_id, lower(display_name))
			DO UPDATE SET external_id = EXCLUDED.external_id, updated_at = now()
			RETURNING id`, id, orgID, strings.TrimSpace(in.DisplayName), in.ExternalID).Scan(&id); err != nil {
			return err
		}
		return s.setMembers(ctx, tx, orgID, id, in.Members)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	g, err := s.loadGroup(r.Context(), orgID, id)
	if err != nil {
		s.lookupErr(w, r, err)
		return
	}
	s.emit(r.Context(), "scim.group.create", audit.Success, "group", id, g.DisplayName,
		map[string]any{"members": len(g.Members)})
	writeJSON(w, http.StatusCreated, g)
}

func (s *Service) replaceGroup(w http.ResponseWriter, r *http.Request) {
	var in Group
	if err := decode(r, &in); err != nil {
		writeScimErr(w, http.StatusBadRequest, "invalidSyntax", err.Error())
		return
	}
	id, orgID := chi.URLParam(r, "id"), orgOf(r)
	ctx := tenant.WithOrg(r.Context(), orgID)
	err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE scim_groups SET display_name = COALESCE(NULLIF($3,''), display_name),
			external_id = NULLIF($4,''), updated_at = now() WHERE id = $1 AND organization_id = $2`,
			id, orgID, strings.TrimSpace(in.DisplayName), in.ExternalID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		if _, err := tx.Exec(ctx, `DELETE FROM scim_group_members WHERE group_id = $1`, id); err != nil {
			return err
		}
		return s.setMembers(ctx, tx, orgID, id, in.Members)
	})
	if err != nil {
		s.lookupErr(w, r, err)
		return
	}
	g, err := s.loadGroup(r.Context(), orgID, id)
	if err != nil {
		s.lookupErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

// patchGroup handles the member add and remove operations a provider uses
// to keep a group in step.
func (s *Service) patchGroup(w http.ResponseWriter, r *http.Request) {
	var in patchOp
	if err := decode(r, &in); err != nil {
		writeScimErr(w, http.StatusBadRequest, "invalidSyntax", err.Error())
		return
	}
	id, orgID := chi.URLParam(r, "id"), orgOf(r)
	ctx := tenant.WithOrg(r.Context(), orgID)
	err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT true FROM scim_groups WHERE id = $1 AND organization_id = $2`,
			id, orgID).Scan(&exists); err != nil {
			return err
		}
		for _, op := range in.Operations {
			path := strings.ToLower(strings.TrimSpace(op.Path))
			switch strings.ToLower(op.Op) {
			case "add":
				if path != "members" && path != "" {
					continue
				}
				var refs []scimRef
				if err := json.Unmarshal(op.Value, &refs); err != nil {
					continue
				}
				if err := s.setMembers(ctx, tx, orgID, id, refs); err != nil {
					return err
				}
			case "replace":
				if path != "members" {
					continue
				}
				var refs []scimRef
				if err := json.Unmarshal(op.Value, &refs); err != nil {
					continue
				}
				if _, err := tx.Exec(ctx, `DELETE FROM scim_group_members WHERE group_id = $1`, id); err != nil {
					return err
				}
				if err := s.setMembers(ctx, tx, orgID, id, refs); err != nil {
					return err
				}
			case "remove":
				// Either members[value eq "x"] in the path, or a value list.
				if v := filterValue(op.Path); v != "" {
					if _, err := tx.Exec(ctx, `DELETE FROM scim_group_members WHERE group_id = $1 AND user_id = $2`, id, v); err != nil {
						return err
					}
					continue
				}
				if path == "members" && len(op.Value) == 0 {
					if _, err := tx.Exec(ctx, `DELETE FROM scim_group_members WHERE group_id = $1`, id); err != nil {
						return err
					}
					continue
				}
				var refs []scimRef
				if err := json.Unmarshal(op.Value, &refs); err != nil {
					continue
				}
				for _, ref := range refs {
					if _, err := tx.Exec(ctx, `DELETE FROM scim_group_members WHERE group_id = $1 AND user_id = $2`, id, ref.Value); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		s.lookupErr(w, r, err)
		return
	}
	g, err := s.loadGroup(r.Context(), orgID, id)
	if err != nil {
		s.lookupErr(w, r, err)
		return
	}
	// Group membership decides role bindings, so a change here is a change
	// to who can do what.
	s.emit(r.Context(), "scim.group.update", audit.Success, "group", id, g.DisplayName,
		map[string]any{"members": len(g.Members)})
	writeJSON(w, http.StatusOK, g)
}

func (s *Service) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id, orgID := chi.URLParam(r, "id"), orgOf(r)
	ctx := tenant.WithOrg(r.Context(), orgID)
	err := s.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM scim_groups WHERE id = $1 AND organization_id = $2`, id, orgID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
	if err != nil {
		s.lookupErr(w, r, err)
		return
	}
	s.emit(r.Context(), "scim.group.delete", audit.Success, "group", id, "", nil)
	w.WriteHeader(http.StatusNoContent)
}

// setMembers adds members, ignoring ids that are not people in this
// organisation: a provider often sends a group that spans more than one.
func (s *Service) setMembers(ctx context.Context, tx pgx.Tx, orgID, groupID string, refs []scimRef) error {
	for _, ref := range refs {
		if ref.Value == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO scim_group_members (group_id, user_id, organization_id)
			SELECT $1, $2, $3 WHERE EXISTS (
				SELECT 1 FROM organization_members m WHERE m.user_id = $2 AND m.organization_id = $3)
			ON CONFLICT DO NOTHING`, groupID, ref.Value, orgID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) loadGroup(ctx context.Context, orgID, id string) (*Group, error) {
	g := &Group{Schemas: []string{schemaGroup}, ID: id, Meta: &meta{ResourceType: "Group", Location: "/scim/v2/Groups/" + id}}
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var external *string
		var created, modified time.Time
		if err := tx.QueryRow(ctx, `SELECT display_name, external_id, created_at, updated_at FROM scim_groups
			WHERE id = $1 AND organization_id = $2`, id, orgID).Scan(&g.DisplayName, &external, &created, &modified); err != nil {
			return err
		}
		if external != nil {
			g.ExternalID = *external
		}
		g.Meta.Created, g.Meta.LastModified = &created, &modified
		rows, err := tx.Query(ctx, `SELECT m.user_id, u.email FROM scim_group_members m
			JOIN users u ON u.id = m.user_id WHERE m.group_id = $1 ORDER BY u.email`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ref scimRef
			if err := rows.Scan(&ref.Value, &ref.Display); err != nil {
				return err
			}
			ref.Ref = "/scim/v2/Users/" + ref.Value
			g.Members = append(g.Members, ref)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return g, nil
}

// --- discovery documents ---------------------------------------------------

func (s *Service) serviceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas":               []string{schemaServiceConfig},
		"documentationUri":      "https://supermcp.dev/docs/scim",
		"patch":                 map[string]any{"supported": true},
		"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]any{"supported": true, "maxResults": maxPageSize},
		"changePassword":        map[string]any{"supported": false},
		"sort":                  map[string]any{"supported": false},
		"etag":                  map[string]any{"supported": false},
		"authenticationSchemes": []any{map[string]any{"type": "oauthbearertoken", "name": "API key", "description": "A supermcp API key with the SCIM permission, sent as a bearer token"}},
	})
}

func (s *Service) resourceTypes(w http.ResponseWriter, _ *http.Request) {
	types := []any{
		map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id": "User", "name": "User", "endpoint": "/Users", "schema": schemaUser},
		map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": schemaGroup},
	}
	writeJSON(w, http.StatusOK, map[string]any{"schemas": []string{schemaListResponse},
		"totalResults": len(types), "startIndex": 1, "itemsPerPage": len(types), "Resources": types})
}

func (s *Service) schemas(w http.ResponseWriter, _ *http.Request) {
	out := []any{
		map[string]any{"id": schemaUser, "name": "User", "description": "A person who can sign in here"},
		map[string]any{"id": schemaGroup, "name": "Group", "description": "A group whose members take its role bindings"},
	}
	writeJSON(w, http.StatusOK, map[string]any{"schemas": []string{schemaListResponse},
		"totalResults": len(out), "startIndex": 1, "itemsPerPage": len(out), "Resources": out})
}

// --- helpers ---------------------------------------------------------------

func orgOf(r *http.Request) string {
	if p, ok := authz.From(r.Context()); ok {
		return p.OrgID
	}
	return ""
}

func decode(r *http.Request, v any) error {
	defer func() { _ = r.Body.Close() }()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("the request body is not valid JSON: %w", err)
	}
	return nil
}

func page(r *http.Request) (start, count int) {
	start, count = 1, 100
	if v, err := strconv.Atoi(r.URL.Query().Get("startIndex")); err == nil && v > 0 {
		start = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("count")); err == nil && v > 0 {
		count = v
	}
	if count > maxPageSize {
		count = maxPageSize
	}
	return start, count
}

// reFilter matches the one filter shape providers use for provisioning:
// a single equality on an attribute.
var reFilter = regexp.MustCompile(`(?i)^\s*(\w+)\s+eq\s+"?([^"]*)"?\s*$`)

func parseFilter(f string) (attr, value string) {
	m := reFilter.FindStringSubmatch(f)
	if m == nil {
		return "", ""
	}
	return strings.ToLower(m[1]), m[2]
}

// reMemberFilter matches members[value eq "id"] in a PATCH path.
var reMemberFilter = regexp.MustCompile(`(?i)members\[\s*value\s+eq\s+"([^"]+)"\s*\]`)

func filterValue(path string) string {
	if m := reMemberFilter.FindStringSubmatch(path); m != nil {
		return m[1]
	}
	return ""
}

func firstEmail(u User) string {
	for _, e := range u.Emails {
		if e.Primary && e.Value != "" {
			return e.Value
		}
	}
	for _, e := range u.Emails {
		if e.Value != "" {
			return e.Value
		}
	}
	if strings.Contains(u.UserName, "@") {
		return u.UserName
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// activeOrDefault treats an absent active field as true, which is what a
// provider means when it creates a user.
func activeOrDefault(u User) bool { return u.Active == nil || *u.Active }

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true"
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr answers with a SCIM error. detail reaches the provider, so it
// is for errors this package words itself; anything else goes to fail.
func writeErr(w http.ResponseWriter, status int, detail string) {
	writeScimErr(w, status, "", detail)
}

// logger is s.Log, or slog.Default when none was set.
func (s *Service) logger() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// fail answers a 500 with reqid.Message and logs err, once, with the
// request id.
func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	id := middleware.GetReqID(r.Context())
	s.logger().ErrorContext(r.Context(), "scim request failed",
		"req_id", id, "method", r.Method, "path", r.URL.Path, "err", err)
	writeErr(w, http.StatusInternalServerError, reqid.Message(id))
}

func writeScimErr(w http.ResponseWriter, status int, typ, detail string) {
	body := map[string]any{"schemas": []string{schemaError}, "status": strconv.Itoa(status), "detail": detail}
	if typ != "" {
		body["scimType"] = typ
	}
	writeJSON(w, status, body)
}

// lookupErr answers a failed read of one resource: 404 when there is no
// such resource, else fail.
func (s *Service) lookupErr(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		writeScimErr(w, http.StatusNotFound, "", "no such resource")
		return
	}
	s.fail(w, r, err)
}
