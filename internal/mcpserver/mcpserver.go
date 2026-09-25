// Package mcpserver stores MCP server definitions: a named endpoint that
// exposes the tools of the connectors attached to it.
package mcpserver

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// ErrNotFound is returned for unknown or invisible servers.
var ErrNotFound = errors.New("MCP server not found")

// ErrInvalidSessions is returned for a session mode that is neither of the
// two below.
var ErrInvalidSessions = errors.New("sessions must be stateless or stateful")

// The two session modes. Stateless is the default, and what every server
// created before the setting existed reads as.
const (
	SessionsStateless = "stateless"
	SessionsStateful  = "stateful"
)

// Server is a stored MCP server. Sessions is SessionsStateless or
// SessionsStateful.
type Server struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"organizationId"`
	Slug         string    `json:"slug"`
	Name         string    `json:"name"`
	Instructions string    `json:"instructions,omitempty"`
	Enabled      bool      `json:"enabled"`
	Sessions     string    `json:"sessions" enum:"stateless,stateful" doc:"stateless answers every request on its own; stateful keeps a session per client on the replica that initialised it, which needs sticky routing"`
	Version      int64     `json:"version" doc:"Send back as expectedVersion when updating"`
	ConnectorIDs []string  `json:"connectorIds" nullable:"false"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// Service manages servers.
type Service struct {
	DB         *tenant.DB
	Connectors *connector.Service
	NewID      func() string
	// Revisions records each change beside the change itself.
	Revisions connector.Recorder
}

func (s *Service) record(ctx context.Context, tx pgx.Tx, id, action string, srv *Server, diff *audit.Diff, actorID string) error {
	if s.Revisions == nil {
		return nil
	}
	return s.Revisions.Record(ctx, tx, "server", id, action, srv, diff, actorID)
}

// New builds the service.
func New(db *tenant.DB, cs *connector.Service, newID func() string) *Service {
	return &Service{DB: db, Connectors: cs, NewID: newID}
}

var reSlug = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Create stores a server.
func (s *Service) Create(ctx context.Context, orgID, name, slug, instructions string, connectorIDs []string, createdBy string) (*Server, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("name is required")
	}
	if slug == "" {
		slug = slugify(name)
	}
	if !reSlug.MatchString(slug) {
		return nil, errors.New("slug must be lowercase kebab-case")
	}
	srv := &Server{ID: s.NewID(), OrgID: orgID, Slug: slug, Name: name, Instructions: instructions, Enabled: true,
		Sessions: SessionsStateless, Version: 1}
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO mcp_servers (id, organization_id, slug, name, instructions, created_by) VALUES ($1,$2,$3,$4,$5,NULLIF($6,''))`,
			srv.ID, orgID, slug, name, instructions, createdBy); err != nil {
			return err
		}
		if err := s.setConnectorsTx(ctx, tx, srv, connectorIDs); err != nil {
			return err
		}
		srv.ConnectorIDs = connectorIDs
		return s.record(ctx, tx, srv.ID, "create", srv, audit.Created(srv), createdBy)
	})
	if err != nil {
		if strings.Contains(err.Error(), "mcp_servers_organization_id_slug_key") {
			return nil, errors.New("a server with this slug already exists")
		}
		return nil, err
	}
	return s.Get(ctx, orgID, srv.ID)
}

// setConnectorsTx replaces the connectors attached to a server. It leaves
// the version to its caller: an update bumps it once for everything it
// changes, so a client that sent expectedVersion N reads N+1 back.
func (s *Service) setConnectorsTx(ctx context.Context, tx pgx.Tx, srv *Server, ids []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM mcp_server_connectors WHERE server_id = $1`, srv.ID); err != nil {
		return err
	}
	for _, cid := range ids {
		// RLS guarantees the connector belongs to this org; the FK guarantees
		// it exists.
		if _, err := tx.Exec(ctx, `INSERT INTO mcp_server_connectors (server_id, connector_id, organization_id) VALUES ($1,$2,$3)`, srv.ID, cid, srv.OrgID); err != nil {
			return err
		}
	}
	return nil
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "server"
	}
	if len(s) > 48 {
		s = strings.TrimRight(s[:48], "-")
	}
	return s
}

const selectServer = `SELECT s.id, s.organization_id, s.slug, s.name, s.instructions, s.enabled, s.sessions, s.version, s.created_at, s.updated_at,
	COALESCE((SELECT array_agg(connector_id ORDER BY connector_id) FROM mcp_server_connectors sc WHERE sc.server_id = s.id), '{}')
	FROM mcp_servers s`

func scan(row pgx.Row) (*Server, error) {
	var srv Server
	if err := row.Scan(&srv.ID, &srv.OrgID, &srv.Slug, &srv.Name, &srv.Instructions, &srv.Enabled, &srv.Sessions, &srv.Version, &srv.CreatedAt, &srv.UpdatedAt, &srv.ConnectorIDs); err != nil {
		return nil, err
	}
	if srv.ConnectorIDs == nil {
		srv.ConnectorIDs = []string{}
	}
	return &srv, nil
}

// Get loads a server by id.
func (s *Service) Get(ctx context.Context, orgID, id string) (*Server, error) {
	var srv *Server
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		srv, err = scan(tx.QueryRow(ctx, selectServer+` WHERE s.id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return srv, err
}

// GetBySlugAnyOrg resolves the endpoint path /mcp/{slug} before a tenant
// is known. It runs through Bypass because the slug is the routing key;
// the caller must still verify membership.
func (s *Service) GetBySlugAnyOrg(ctx context.Context, slug string) (*Server, error) {
	var srv *Server
	err := s.DB.Bypass(ctx, "mcp-route:"+slug, func(tx pgx.Tx) error {
		var err error
		srv, err = scan(tx.QueryRow(ctx, selectServer+` WHERE s.slug = $1 ORDER BY s.created_at LIMIT 1`, slug))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return srv, err
}

// GetByIDAnyOrg resolves /mcp/{id} the same way.
func (s *Service) GetByIDAnyOrg(ctx context.Context, id string) (*Server, error) {
	var srv *Server
	err := s.DB.Bypass(ctx, "mcp-route:"+id, func(tx pgx.Tx) error {
		var err error
		srv, err = scan(tx.QueryRow(ctx, selectServer+` WHERE s.id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return srv, err
}

// List returns the org's servers.
func (s *Service) List(ctx context.Context, orgID string) ([]*Server, error) {
	var out []*Server
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectServer+` ORDER BY s.created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			srv, err := scan(rows)
			if err != nil {
				return err
			}
			out = append(out, srv)
		}
		return rows.Err()
	})
	if out == nil {
		out = []*Server{}
	}
	return out, err
}

// UpdateInput is a partial update.
type UpdateInput struct {
	Name         *string
	Instructions *string
	Enabled      *bool
	// Sessions is SessionsStateless or SessionsStateful.
	Sessions     *string
	ConnectorIDs *[]string
	// ExpectedVersion, when not zero, must equal the stored version; see
	// connector.CheckVersion.
	ExpectedVersion int64
	// ActorID names who made the change, for the revision it produces.
	ActorID string
}

// Update applies a partial update.
func (s *Service) Update(ctx context.Context, orgID, id string, in UpdateInput) (*Server, error) {
	if in.Sessions != nil && *in.Sessions != SessionsStateless && *in.Sessions != SessionsStateful {
		return nil, ErrInvalidSessions
	}
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		srv, err := scan(tx.QueryRow(ctx, selectServer+` WHERE s.id = $1 FOR UPDATE OF s`, id))
		if err != nil {
			return err
		}
		if err := connector.CheckVersion("server", in.ExpectedVersion, srv.Version); err != nil {
			return err
		}
		before := *srv
		if in.Name != nil {
			srv.Name = *in.Name
		}
		if in.Instructions != nil {
			srv.Instructions = *in.Instructions
		}
		if in.Enabled != nil {
			srv.Enabled = *in.Enabled
		}
		if in.Sessions != nil {
			srv.Sessions = *in.Sessions
		}
		if _, err := tx.Exec(ctx, `UPDATE mcp_servers SET name=$2, instructions=$3, enabled=$4, sessions=$5, version=version+1, updated_at=now() WHERE id=$1`,
			id, srv.Name, srv.Instructions, srv.Enabled, srv.Sessions); err != nil {
			return err
		}
		if in.ConnectorIDs != nil {
			if err := s.setConnectorsTx(ctx, tx, srv, *in.ConnectorIDs); err != nil {
				return err
			}
			// The struct scanned above does not carry them, and a snapshot
			// that claims no connectors were attached would detach them all
			// when restored.
			srv.ConnectorIDs = *in.ConnectorIDs
		}
		after := *srv
		after.Version++
		return s.record(ctx, tx, id, "update", &after, audit.Changes(before, &after), in.ActorID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, orgID, id)
}

// Delete removes a server.
func (s *Service) Delete(ctx context.Context, orgID, id, actorID string) error {
	return s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		srv, err := scan(tx.QueryRow(ctx, selectServer+` WHERE s.id = $1 FOR UPDATE OF s`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mcp_servers WHERE id = $1`, id); err != nil {
			return err
		}
		return s.record(ctx, tx, id, "delete", srv, audit.Deleted(srv), actorID)
	})
}

// Surface is everything needed to serve a server: its enabled tools with
// their connectors, and the composed instructions.
type Surface struct {
	Server       *Server
	Instructions string
	Tools        []SurfaceTool
}

// SurfaceTool is one servable tool.
type SurfaceTool struct {
	Tool      *connector.Tool
	Connector *connector.Connector
}

// Surface loads the tools of every enabled connector attached to a server.
func (s *Service) Surface(ctx context.Context, srv *Server) (*Surface, error) {
	out := &Surface{Server: srv}
	var parts []string
	if strings.TrimSpace(srv.Instructions) != "" {
		parts = append(parts, strings.TrimSpace(srv.Instructions))
	}
	for _, cid := range srv.ConnectorIDs {
		c, err := s.Connectors.Get(ctx, srv.OrgID, cid)
		if err != nil {
			if errors.Is(err, connector.ErrNotFound) {
				continue
			}
			return nil, err
		}
		if !c.Enabled {
			continue
		}
		if strings.TrimSpace(c.Instructions) != "" {
			parts = append(parts, "## "+c.Name+"\n\n"+strings.TrimSpace(c.Instructions))
		}
		tools, err := s.Connectors.Tools(ctx, srv.OrgID, cid)
		if err != nil {
			return nil, err
		}
		for _, t := range tools {
			if t.Enabled && t.DeprecatedAt == nil {
				out.Tools = append(out.Tools, SurfaceTool{Tool: t, Connector: c})
			}
		}
	}
	out.Instructions = strings.Join(parts, "\n\n")
	return out, nil
}
