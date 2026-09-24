package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// A service account is a principal that is not a person: a pipeline, a
// scheduler, another service. It lives in one organisation, takes the same
// role bindings as a user, and authenticates with client credentials, so
// the token it gets carries the same claims a person's token would.

// Errors.
var (
	ErrServiceAccountUnknown  = errors.New("unknown service account")
	ErrServiceAccountDisabled = errors.New("this service account is disabled")
)

// ServiceAccount is the stored record. The secret is never readable after
// creation; only its hash is kept.
type ServiceAccount struct {
	ID          string     `json:"id"`
	OrgID       string     `json:"organizationId"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	ClientID    string     `json:"clientId"`
	ServerID    string     `json:"serverId,omitempty"`
	Scopes      []string   `json:"scopes"`
	LastUsedAt  *time.Time `json:"lastUsedAt,omitempty"`
	DisabledAt  *time.Time `json:"disabledAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	// Secret is set once, on creation and on rotation.
	Secret string `json:"secret,omitempty"`
}

// ServiceAccountInput is what an administrator supplies.
type ServiceAccountInput struct {
	Name        string
	Description string
	ServerID    string
	Scopes      []string
}

// CreateServiceAccount registers an account and returns its one-time
// secret.
func (s *Service) CreateServiceAccount(ctx context.Context, orgID, actorID string, in ServiceAccountInput) (*ServiceAccount, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, errors.New("a name is required")
	}
	sa := &ServiceAccount{ID: s.NewID(), OrgID: orgID, Name: strings.TrimSpace(in.Name),
		Description: in.Description, ServerID: in.ServerID, Scopes: normaliseScopes(in.Scopes)}
	sa.ClientID = "sms_" + randomToken(16)
	secret := randomToken(32)
	hash := sha256.Sum256([]byte(secret))
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO service_accounts
			(id, organization_id, name, description, client_id, secret_hash, secret_prefix, server_id, scopes, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9,$10)`,
			sa.ID, orgID, sa.Name, sa.Description, sa.ClientID, hash[:], secret[:6], sa.ServerID, sa.Scopes, actorID)
		return err
	})
	if err != nil {
		return nil, err
	}
	sa.Secret = secret
	sa.CreatedAt = s.now()
	return sa, nil
}

// ListServiceAccounts returns an organisation's accounts.
func (s *Service) ListServiceAccounts(ctx context.Context, orgID string) ([]ServiceAccount, error) {
	out := []ServiceAccount{}
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, organization_id, name, description, client_id,
			COALESCE(server_id,''), scopes, last_used_at, disabled_at, created_at
			FROM service_accounts WHERE organization_id = $1 ORDER BY name`, orgID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a ServiceAccount
			if err := rows.Scan(&a.ID, &a.OrgID, &a.Name, &a.Description, &a.ClientID,
				&a.ServerID, &a.Scopes, &a.LastUsedAt, &a.DisabledAt, &a.CreatedAt); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// RotateServiceAccountSecret issues a new secret and invalidates the old
// one immediately: a leaked secret is the reason to rotate, so a grace
// period would defeat it.
func (s *Service) RotateServiceAccountSecret(ctx context.Context, orgID, id string) (string, error) {
	secret := randomToken(32)
	hash := sha256.Sum256([]byte(secret))
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE service_accounts SET secret_hash = $3, secret_prefix = $4, updated_at = now()
			WHERE id = $1 AND organization_id = $2`, id, orgID, hash[:], secret[:6])
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrServiceAccountUnknown
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return secret, nil
}

// SetServiceAccountDisabled turns an account off or on.
func (s *Service) SetServiceAccountDisabled(ctx context.Context, orgID, id string, disabled bool) error {
	return s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var at any
		if disabled {
			at = s.now()
		}
		tag, err := tx.Exec(ctx, `UPDATE service_accounts SET disabled_at = $3, updated_at = now()
			WHERE id = $1 AND organization_id = $2`, id, orgID, at)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrServiceAccountUnknown
		}
		return nil
	})
}

// DeleteServiceAccount removes an account and the bindings that named it.
func (s *Service) DeleteServiceAccount(ctx context.Context, orgID, id string) error {
	return s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM role_bindings WHERE organization_id = $1
			AND principal_kind = 'service_account' AND principal_id = $2`, orgID, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE api_keys SET revoked_at = now(), revoked_reason = 'service account deleted'
			WHERE organization_id = $1 AND principal_kind = 'service_account' AND principal_id = $2 AND revoked_at IS NULL`,
			orgID, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM service_accounts WHERE id = $1 AND organization_id = $2`, id, orgID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrServiceAccountUnknown
		}
		return nil
	})
}

// AuthenticateServiceAccount verifies client credentials and returns the
// principal they stand for. It runs before a tenant is known, so it reads
// through the pre-authentication function.
func (s *Service) AuthenticateServiceAccount(ctx context.Context, clientID, secret string) (*authz.Principal, []string, error) {
	var id, orgID, name, serverID string
	var hash []byte
	var scopes []string
	var disabled *time.Time
	var server *string
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, organization_id, name, secret_hash, server_id, scopes, disabled_at
			FROM auth_service_account($1)`, clientID).Scan(&id, &orgID, &name, &hash, &server, &scopes, &disabled)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// Verify against a dummy anyway: a missing account and a wrong
		// secret should take the same time.
		dummy := sha256.Sum256([]byte("supermcp-dummy-service-account-secret"))
		_ = subtle.ConstantTimeCompare(dummy[:], dummy[:])
		return nil, nil, ErrServiceAccountUnknown
	}
	if err != nil {
		return nil, nil, err
	}
	got := sha256.Sum256([]byte(secret))
	if len(hash) == 0 || subtle.ConstantTimeCompare(got[:], hash) != 1 {
		return nil, nil, ErrServiceAccountUnknown
	}
	if disabled != nil {
		return nil, nil, ErrServiceAccountDisabled
	}
	if server != nil {
		serverID = *server
	}
	_ = s.DB.Pre(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT auth_service_account_used($1)`, id)
		return err
	})
	return &authz.Principal{
		Kind: authz.KindServiceAccount, ID: id, OrgID: orgID, ServerID: serverID,
		AuthMethod: "client_credentials", Email: name,
	}, scopes, nil
}

func normaliseScopes(in []string) []string {
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		switch s {
		case authz.ScopeToolsRead, authz.ScopeToolsInvoke, authz.ScopeOrg:
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		out = []string{authz.ScopeToolsRead, authz.ScopeToolsInvoke}
	}
	return out
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
