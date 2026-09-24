// Package connector stores upstream definitions and their credentials, and
// resolves them into what the engines need at call time.
package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/tenant"
	"github.com/supermcpco/supermcp/internal/upstreamauth"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// Errors.
var (
	// ErrNotFound is returned for unknown or invisible connectors.
	ErrNotFound = errors.New("connector not found")
	// ErrMissingCredential means a required credential was not supplied.
	ErrMissingCredential = errors.New("missing credential")
)

// Connector is the stored record (credential values never included).
type Connector struct {
	ID           string            `json:"id"`
	OrgID        string            `json:"organizationId"`
	Name         string            `json:"name"`
	Transport    adapter.Transport `json:"transport"`
	Auth         adapter.Auth      `json:"auth"`
	Instructions string            `json:"instructions,omitempty"`
	CatalogSlug  string            `json:"catalogSlug,omitempty"`
	CatalogHash  string            `json:"catalogHash,omitempty"`
	ReadOnly     bool              `json:"readOnly"`
	Enabled      bool              `json:"enabled"`
	Version      int64             `json:"version"`
	ToolCount    int               `json:"toolCount"`
	Credentials  []CredentialInfo  `json:"credentials"`
	CreatedAt    time.Time         `json:"createdAt"`
	UpdatedAt    time.Time         `json:"updatedAt"`
}

// CredentialInfo says which credentials exist, never their values.
type CredentialInfo struct {
	Name     string `json:"name"`
	Set      bool   `json:"set"`
	Secret   bool   `json:"secret"`
	Required bool   `json:"required"`
}

// Tool is a stored tool.
type Tool struct {
	ID           string        `json:"id"`
	ConnectorID  string        `json:"connectorId"`
	Name         string        `json:"name"`
	Definition   *adapter.Tool `json:"definition"`
	OperationID  string        `json:"operationId,omitempty"`
	Enabled      bool          `json:"enabled"`
	DeprecatedAt *time.Time    `json:"deprecatedAt,omitempty"`
	Version      int64         `json:"version"`
}

// Service is the connector service.
type Service struct {
	DB     *tenant.DB
	Sealer *secrets.Sealer
	NewID  func() string
	// Revisions records what each change did, in the same transaction as
	// the change. A history that can be lost separately from the thing it
	// describes is worse than none: it looks complete when it is not.
	Revisions Recorder
}

// Recorder is the part of the revisions service this package needs. It is
// an interface so the dependency points this way and not the other.
type Recorder interface {
	Record(ctx context.Context, tx pgx.Tx, kind, entityID, action string, entity any, diff *audit.Diff, actorID string) error
}

// record writes a revision when one is configured.
func (s *Service) record(ctx context.Context, tx pgx.Tx, kind, entityID, action string, entity any, diff *audit.Diff, actorID string) error {
	if s.Revisions == nil {
		return nil
	}
	return s.Revisions.Record(ctx, tx, kind, entityID, action, entity, diff, actorID)
}

// New builds the service.
func New(db *tenant.DB, sealer *secrets.Sealer, newID func() string) *Service {
	return &Service{DB: db, Sealer: sealer, NewID: newID}
}

// Install creates a connector (and its tools) from a catalog adapter.
func (s *Service) Install(ctx context.Context, orgID string, a *adapter.Adapter, hash string, creds map[string]string, createdBy string) (*Connector, error) {
	c := &Connector{ID: s.NewID(), OrgID: orgID, Name: a.Metadata.Name, Transport: a.Transport, Auth: a.Auth,
		Instructions: a.Instructions, CatalogSlug: a.Metadata.Slug, CatalogHash: hash, ReadOnly: true, Enabled: true, Version: 1}
	// Required credentials must be present at install time.
	for _, name := range a.Credentials.Keys {
		if a.Credentials.Values[name].Required && strings.TrimSpace(creds[name]) == "" {
			return nil, fmt.Errorf("%w: %s is required to install %s", ErrMissingCredential, name, a.Metadata.Name)
		}
	}
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		if err := s.insert(ctx, tx, c, createdBy); err != nil {
			return err
		}
		for i := range a.Tools {
			t := a.Tools[i]
			if err := s.insertTool(ctx, tx, c, &t); err != nil {
				return err
			}
		}
		if err := s.setCredentialsTx(ctx, tx, c, a, creds); err != nil {
			return err
		}
		return s.record(ctx, tx, "connector", c.ID, "create", c, audit.Created(c), createdBy)
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, orgID, c.ID)
}

// CreateInput describes a hand-made connector.
type CreateInput struct {
	Name         string
	Transport    adapter.Transport
	Auth         adapter.Auth
	Instructions string
	ReadOnly     *bool
	Tools        []adapter.Tool
	Credentials  map[string]string
	CreatedBy    string
}

// Create stores a custom connector.
func (s *Service) Create(ctx context.Context, orgID string, in CreateInput) (*Connector, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, errors.New("name is required")
	}
	c := &Connector{ID: s.NewID(), OrgID: orgID, Name: in.Name, Transport: in.Transport, Auth: in.Auth, Instructions: in.Instructions, ReadOnly: true, Enabled: true, Version: 1}
	if in.ReadOnly != nil {
		c.ReadOnly = *in.ReadOnly
	}
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		if err := s.insert(ctx, tx, c, in.CreatedBy); err != nil {
			return err
		}
		for i := range in.Tools {
			if err := s.insertTool(ctx, tx, c, &in.Tools[i]); err != nil {
				return err
			}
		}
		for name, v := range in.Credentials {
			if err := s.sealCredential(ctx, tx, c, name, v, true); err != nil {
				return err
			}
		}
		return s.record(ctx, tx, "connector", c.ID, "create", c, audit.Created(c), in.CreatedBy)
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, orgID, c.ID)
}

func (s *Service) insert(ctx context.Context, tx pgx.Tx, c *Connector, createdBy string) error {
	tr, _ := json.Marshal(c.Transport)
	// The auth block holds {{env.X}} placeholders, never secret values;
	// the values live sealed in connector_credentials.
	au, _ := json.Marshal(c.Auth) //nolint:gosec // placeholders only
	_, err := tx.Exec(ctx, `INSERT INTO connectors (id, organization_id, name, transport, auth, instructions, catalog_slug, catalog_hash, read_only, enabled, version, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),NULLIF($8,''),$9,$10,$11,NULLIF($12,''))`,
		c.ID, c.OrgID, c.Name, tr, au, c.Instructions, c.CatalogSlug, c.CatalogHash, c.ReadOnly, c.Enabled, c.Version, createdBy)
	return err
}

func (s *Service) insertTool(ctx context.Context, tx pgx.Tx, c *Connector, t *adapter.Tool) error {
	def, err := adapterToolJSON(t)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO tools (id, connector_id, organization_id, name, definition, enabled) VALUES ($1,$2,$3,$4,$5,true)`,
		s.NewID(), c.ID, c.OrgID, t.Name, def)
	return err
}

func adapterToolJSON(t *adapter.Tool) ([]byte, error) {
	// Reuse the adapter package's ordered JSON encoding via a single-tool doc.
	a := &adapter.Adapter{Tools: []adapter.Tool{*t}}
	raw, err := adapter.MarshalJSON(a)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Tools) != 1 {
		return nil, fmt.Errorf("encode tool: %w", err)
	}
	return doc.Tools[0], nil
}

func (s *Service) setCredentialsTx(ctx context.Context, tx pgx.Tx, c *Connector, a *adapter.Adapter, creds map[string]string) error {
	for _, name := range a.Credentials.Keys {
		v, ok := creds[name]
		if !ok || v == "" {
			continue
		}
		if err := s.sealCredential(ctx, tx, c, name, v, a.Credentials.Values[name].Secret); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) sealCredential(ctx context.Context, tx pgx.Tx, c *Connector, name, value string, secret bool) error {
	ct, err := s.Sealer.Seal(ctx, secrets.ScopeOrg(c.OrgID), []byte(value), secrets.AAD{Table: "connector_credentials", Column: "value_enc", RowID: c.ID + "/" + name, OrgID: c.OrgID})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO connector_credentials (connector_id, organization_id, name, value_enc, secret) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (connector_id, name) DO UPDATE SET value_enc = EXCLUDED.value_enc, secret = EXCLUDED.secret, updated_at = now()`,
		c.ID, c.OrgID, name, ct, secret)
	return err
}

// SetCredentials replaces the given credentials (others untouched) and
// bumps the version so cached clients rebuild.
func (s *Service) SetCredentials(ctx context.Context, orgID, id string, creds map[string]string) error {
	return s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		c := &Connector{ID: id, OrgID: orgID}
		for name, v := range creds {
			if v == "" {
				if _, err := tx.Exec(ctx, `DELETE FROM connector_credentials WHERE connector_id = $1 AND name = $2`, id, name); err != nil {
					return err
				}
				continue
			}
			if err := s.sealCredential(ctx, tx, c, name, v, true); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `UPDATE connectors SET version = version + 1, updated_at = now() WHERE id = $1`, id)
		return err
	})
}

const selectConnector = `SELECT c.id, c.organization_id, c.name, c.transport, c.auth, c.instructions, COALESCE(c.catalog_slug,''), COALESCE(c.catalog_hash,''),
	c.read_only, c.enabled, c.version, c.created_at, c.updated_at, (SELECT count(*) FROM tools t WHERE t.connector_id = c.id AND t.enabled)
	FROM connectors c`

func scanConnector(row pgx.Row) (*Connector, error) {
	var c Connector
	var tr, au []byte
	if err := row.Scan(&c.ID, &c.OrgID, &c.Name, &tr, &au, &c.Instructions, &c.CatalogSlug, &c.CatalogHash, &c.ReadOnly, &c.Enabled, &c.Version, &c.CreatedAt, &c.UpdatedAt, &c.ToolCount); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(tr, &c.Transport); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(au, &c.Auth); err != nil {
		return nil, err
	}
	return &c, nil
}

// Get loads one connector with credential presence.
func (s *Service) Get(ctx context.Context, orgID, id string) (*Connector, error) {
	var c *Connector
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		c, err = scanConnector(tx.QueryRow(ctx, selectConnector+` WHERE c.id = $1`, id))
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT name, secret FROM connector_credentials WHERE connector_id = $1 ORDER BY name`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		set := map[string]bool{}
		for rows.Next() {
			var name string
			var secret bool
			if err := rows.Scan(&name, &secret); err != nil {
				return err
			}
			set[name] = secret
		}
		for _, name := range referencedCredentials(c) {
			_, ok := set[name]
			c.Credentials = append(c.Credentials, CredentialInfo{Name: name, Set: ok, Secret: !ok || set[name], Required: true})
		}
		return rows.Err()
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// referencedCredentials lists {{env.X}} names used by transport and auth.
func referencedCredentials(c *Connector) []string {
	raw, _ := json.Marshal(struct {
		T adapter.Transport
		A adapter.Auth
	}{c.Transport, c.Auth})
	seen := map[string]bool{}
	var out []string
	for i := 0; i+6 < len(raw); i++ {
		if string(raw[i:i+6]) == "{{env." {
			j := i + 6
			for j < len(raw) && raw[j] != '}' && raw[j] != ' ' && raw[j] != '|' {
				j++
			}
			name := string(raw[i+6 : j])
			if name != "" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// List returns the org's connectors.
func (s *Service) List(ctx context.Context, orgID string) ([]*Connector, error) {
	var out []*Connector
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectConnector+` ORDER BY c.created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanConnector(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if out == nil {
		out = []*Connector{}
	}
	return out, err
}

// UpdateInput is a partial update.
type UpdateInput struct {
	Name         *string
	Instructions *string
	ReadOnly     *bool
	Enabled      *bool
	Transport    *adapter.Transport
	Auth         *adapter.Auth
	// ActorID names who made the change, for the revision it produces.
	ActorID string
}

// Update applies a partial update and bumps the version.
func (s *Service) Update(ctx context.Context, orgID, id string, in UpdateInput) (*Connector, error) {
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		c, err := scanConnector(tx.QueryRow(ctx, selectConnector+` WHERE c.id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		before := *c
		if in.Name != nil {
			c.Name = *in.Name
		}
		if in.Instructions != nil {
			c.Instructions = *in.Instructions
		}
		if in.ReadOnly != nil {
			c.ReadOnly = *in.ReadOnly
		}
		if in.Enabled != nil {
			c.Enabled = *in.Enabled
		}
		if in.Transport != nil {
			c.Transport = *in.Transport
		}
		if in.Auth != nil {
			c.Auth = *in.Auth
		}
		tr, _ := json.Marshal(c.Transport)
		au, _ := json.Marshal(c.Auth) //nolint:gosec // placeholders only
		if _, err = tx.Exec(ctx, `UPDATE connectors SET name=$2, instructions=$3, read_only=$4, enabled=$5, transport=$6, auth=$7, version=version+1, updated_at=now() WHERE id=$1`,
			id, c.Name, c.Instructions, c.ReadOnly, c.Enabled, tr, au); err != nil {
			return err
		}
		// The row's version was bumped in SQL, so the snapshot says so too.
		after := *c
		after.Version++
		return s.record(ctx, tx, "connector", id, "update", &after, audit.Changes(before, &after), in.ActorID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, orgID, id)
}

// Delete removes a connector and everything under it.
func (s *Service) Delete(ctx context.Context, orgID, id, actorID string) error {
	return s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		// The connector is read before it goes, because a revision of a
		// deletion that records nothing is not a record of anything.
		c, err := scanConnector(tx.QueryRow(ctx, selectConnector+` WHERE c.id = $1 FOR UPDATE`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM connectors WHERE id = $1`, id); err != nil {
			return err
		}
		return s.record(ctx, tx, "connector", id, "delete", c, audit.Deleted(c), actorID)
	})
}

// Tools lists a connector's tools.
func (s *Service) Tools(ctx context.Context, orgID, connectorID string) ([]*Tool, error) {
	var out []*Tool
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, connector_id, name, definition, COALESCE(operation_id,''), enabled, deprecated_at, version FROM tools WHERE connector_id = $1 ORDER BY name`, connectorID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanTool(rows)
			if err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	if out == nil {
		out = []*Tool{}
	}
	return out, err
}

func scanTool(row pgx.Row) (*Tool, error) {
	var t Tool
	var def []byte
	if err := row.Scan(&t.ID, &t.ConnectorID, &t.Name, &def, &t.OperationID, &t.Enabled, &t.DeprecatedAt, &t.Version); err != nil {
		return nil, err
	}
	td, err := ParseToolJSON(def)
	if err != nil {
		return nil, err
	}
	t.Definition = td
	return &t, nil
}

// ParseToolJSON decodes a stored tool definition, keeping key order.
func ParseToolJSON(def []byte) (*adapter.Tool, error) {
	var t adapter.Tool
	if err := json.Unmarshal(def, &t); err != nil {
		return nil, err
	}
	// Free-form nodes come back nil from encoding/json; re-read them.
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(def, &raw)
	if v, ok := raw["input"]; ok {
		t.Input, _ = adapter.NodeFromJSON(v)
	}
	if v, ok := raw["output"]; ok {
		t.Output, _ = adapter.NodeFromJSON(v)
	}
	if op, ok := raw["operation"]; ok {
		var opRaw map[string]json.RawMessage
		_ = json.Unmarshal(op, &opRaw)
		if v, ok := opRaw["query"]; ok {
			t.Operation.Query, _ = adapter.NodeFromJSON(v)
		}
		if v, ok := opRaw["variables"]; ok {
			t.Operation.Variables, _ = adapter.NodeFromJSON(v)
		}
		if v, ok := opRaw["value"]; ok {
			t.Operation.Value, _ = adapter.NodeFromJSON(v)
		}
		if v, ok := opRaw["argsMap"]; ok {
			t.Operation.ArgsMap, _ = adapter.NodeFromJSON(v)
		}
		if b, ok := opRaw["body"]; ok {
			var bodyRaw map[string]json.RawMessage
			_ = json.Unmarshal(b, &bodyRaw)
			if t.Operation.Body == nil {
				t.Operation.Body = &adapter.Body{}
			}
			if v, ok := bodyRaw["value"]; ok {
				t.Operation.Body.Value, _ = adapter.NodeFromJSON(v)
			}
		}
	}
	return &t, nil
}

// SetToolEnabled toggles a tool.
func (s *Service) SetToolEnabled(ctx context.Context, orgID, toolID string, enabled bool) error {
	return s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE tools SET enabled = $2, version = version + 1, updated_at = now() WHERE id = $1`, toolID, enabled)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx, `UPDATE connectors SET version = version + 1 WHERE id = (SELECT connector_id FROM tools WHERE id = $1)`, toolID)
		return err
	})
}

// Resolved is a connector ready for execution.
type Resolved struct {
	Connector *engine.Connector
	Env       map[string]string
}

// Resolve loads a connector and decrypts its credentials.
func (s *Service) Resolve(ctx context.Context, orgID, id string) (*Resolved, error) {
	var c *Connector
	env := map[string]string{}
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		c, err = scanConnector(tx.QueryRow(ctx, selectConnector+` WHERE c.id = $1`, id))
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT name, value_enc FROM connector_credentials WHERE connector_id = $1`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			var ct []byte
			if err := rows.Scan(&name, &ct); err != nil {
				return err
			}
			pt, err := s.Sealer.Open(ctx, ct, secrets.AAD{Table: "connector_credentials", Column: "value_enc", RowID: id + "/" + name, OrgID: orgID})
			if err != nil {
				return fmt.Errorf("decrypt credential %s: %w", name, err)
			}
			env[name] = string(pt)
		}
		return rows.Err()
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !c.Enabled {
		return nil, errors.New("connector is disabled")
	}
	return &Resolved{Env: env, Connector: &engine.Connector{
		ID: c.ID, Version: c.Version, Type: c.Transport.Type, BaseURL: c.Transport.BaseURL, DSN: c.Transport.DSN,
		Driver: c.Transport.Driver, Headers: c.Transport.Headers, Auth: c.Auth, ReadOnly: c.ReadOnly,
	}}, nil
}

// TokenStore persists upstream tokens sealed per connector.
type TokenStore struct {
	S     *Service
	OrgID string
}

var _ upstreamauth.TokenStore = (*TokenStore)(nil)

func (t *TokenStore) aad(id string) secrets.AAD {
	return secrets.AAD{Table: "connector_tokens", Column: "token_enc", RowID: id, OrgID: t.OrgID}
}

func (t *TokenStore) Get(ctx context.Context, id string) (*upstreamauth.Token, bool, error) {
	var ct []byte
	var exp time.Time
	err := t.S.DB.Tx(tenant.WithOrg(ctx, t.OrgID), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT token_enc, expires_at FROM connector_tokens WHERE connector_id = $1`, id).Scan(&ct, &exp)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	pt, err := t.S.Sealer.Open(ctx, ct, t.aad(id))
	if err != nil {
		return nil, false, err
	}
	var tok upstreamauth.Token
	if err := json.Unmarshal(pt, &tok); err != nil {
		return nil, false, err
	}
	tok.ExpiresAt = exp
	return &tok, true, nil
}

func (t *TokenStore) Put(ctx context.Context, id string, tok *upstreamauth.Token) error {
	pt, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	ct, err := t.S.Sealer.Seal(ctx, secrets.ScopeOrg(t.OrgID), pt, t.aad(id))
	if err != nil {
		return err
	}
	return t.S.DB.Tx(tenant.WithOrg(ctx, t.OrgID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO connector_tokens (connector_id, organization_id, token_enc, expires_at) VALUES ($1,$2,$3,$4)
			ON CONFLICT (connector_id) DO UPDATE SET token_enc = EXCLUDED.token_enc, expires_at = EXCLUDED.expires_at, updated_at = now()`, id, t.OrgID, ct, tok.ExpiresAt)
		return err
	})
}

func (t *TokenStore) Delete(ctx context.Context, id string) error {
	return t.S.DB.Tx(tenant.WithOrg(ctx, t.OrgID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM connector_tokens WHERE connector_id = $1`, id)
		return err
	})
}

// RotateRefreshToken stores a provider-rotated refresh token as the
// connector's credential, replacing the configured one.
func (s *Service) RotateRefreshToken(ctx context.Context, orgID, id, refreshToken string) error {
	c, err := s.Get(ctx, orgID, id)
	if err != nil {
		return err
	}
	name := envName(c.Auth.RefreshToken)
	if name == "" {
		return nil // refresh token was a literal; the token store already holds it
	}
	return s.SetCredentials(ctx, orgID, id, map[string]string{name: refreshToken})
}

func envName(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{{env.") && strings.HasSuffix(s, "}}") {
		return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "{{env."), "}}"))
	}
	return ""
}
