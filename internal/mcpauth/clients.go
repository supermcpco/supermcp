package mcpauth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Registered clients belong to the instance, not to a workspace: one MCP
// client registers once and is then used by people in any workspace. So
// deciding on a client registered under `approval` mode is the instance
// operator's call, made from the command line, not a workspace admin's.

// ClientInfo is a registered client as the operator sees it.
type ClientInfo struct {
	ClientID       string     `json:"client_id"`
	Name           string     `json:"client_name"`
	RedirectURIs   []string   `json:"redirect_uris"`
	AuthMethod     string     `json:"token_endpoint_auth_method"`
	Status         string     `json:"status"`
	RegistrationIP string     `json:"registration_ip,omitempty"`
	DecidedBy      string     `json:"decided_by,omitempty"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// ErrClientNotFound is returned for a client_id that was never registered.
var ErrClientNotFound = errors.New("no client is registered with that client_id")

// ListClients returns registered clients, newest first. An empty status
// lists every client.
func (o *OAuth) ListClients(ctx context.Context, status string) ([]ClientInfo, error) {
	out := []ClientInfo{}
	err := o.DB.Bypass(ctx, "oauth-clients-list", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT client_id, client_name, redirect_uris, token_endpoint_auth_method, status,
			COALESCE(host(registration_ip),''), COALESCE(approved_by,''), approved_at, last_used_at, created_at
			FROM oauth_clients WHERE ($1 = '' OR status = $1) ORDER BY created_at DESC`, status)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c ClientInfo
			if err := rows.Scan(&c.ClientID, &c.Name, &c.RedirectURIs, &c.AuthMethod, &c.Status,
				&c.RegistrationIP, &c.DecidedBy, &c.DecidedAt, &c.LastUsedAt, &c.CreatedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// DecideClient approves or rejects a registered client and returns what it
// was before. Rejecting an approved client also revokes every refresh
// token it holds, since a rejection that left its sessions running would
// only stop new sign-ins.
func (o *OAuth) DecideClient(ctx context.Context, clientID string, approve bool, by string) (before ClientInfo, revoked int64, err error) {
	status := "rejected"
	if approve {
		status = "approved"
	}
	err = o.DB.Bypass(ctx, "oauth-client-decide", func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT client_id, client_name, status FROM oauth_clients WHERE client_id = $1 FOR UPDATE`, clientID).
			Scan(&before.ClientID, &before.Name, &before.Status); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrClientNotFound
			}
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE oauth_clients SET status = $2, approved_by = NULLIF($3,''), approved_at = now()
			WHERE client_id = $1`, clientID, status, by); err != nil {
			return err
		}
		if approve {
			return nil
		}
		tag, err := tx.Exec(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE client_id = $1 AND revoked_at IS NULL`, clientID)
		revoked = tag.RowsAffected()
		return err
	})
	return before, revoked, err
}
