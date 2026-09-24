package compliance

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/authz"
)

// Every query in this file runs inside one workspace's transaction, so
// row-level security decides what it sees. None of them names
// organization_id: the policies already do, and a predicate that repeats
// them would hide the day one of them stopped working.

func readBindings(ctx context.Context, tx pgx.Tx, now time.Time) ([]rawBinding, error) {
	rows, err := tx.Query(ctx, `
SELECT b.id, b.principal_kind, b.principal_id, b.role_id, r.name, r.permissions,
       b.scope_kind, COALESCE(b.scope_id, ''), b.source, b.expires_at, b.created_at, COALESCE(b.created_by, '')
FROM role_bindings b JOIN roles r ON r.id = b.role_id
ORDER BY b.created_at, b.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []rawBinding{}
	for rows.Next() {
		var b rawBinding
		if err := rows.Scan(&b.ID, &b.principalKind, &b.principalID, &b.RoleID, &b.RoleName, &b.Permissions,
			&b.ScopeKind, &b.ScopeID, &b.Source, &b.ExpiresAt, &b.CreatedAt, &b.CreatedBy); err != nil {
			return nil, err
		}
		b.Permissions = sortedStrings(b.Permissions)
		for _, perm := range b.Permissions {
			if privileged[authz.Permission(perm)] {
				b.Privileged = append(b.Privileged, perm)
			}
		}
		b.Expired = b.ExpiresAt != nil && b.ExpiresAt.Before(now)
		out = append(out, b)
	}
	return out, rows.Err()
}

// lastUse is the newest thing this instance recorded a principal doing,
// and which record it came from.
type lastUse struct {
	At   time.Time
	From string
}

// readLastUse keys by principal id alone rather than by (kind, id).
// A call made with an API key is recorded against the kind "api_key" and
// the id of the principal the key belongs to, so keying on the kind would
// file a service account's tool calls under a principal that does not
// exist. Ids are generated and do not collide between the two tables, so
// the id is the reliable half of the pair.
func readLastUse(ctx context.Context, tx pgx.Tx) (map[string]lastUse, error) {
	out := map[string]lastUse{}
	record := func(id string, at *time.Time, from string) {
		if id == "" || at == nil || at.IsZero() {
			return
		}
		if cur, ok := out[id]; !ok || at.After(cur.At) {
			out[id] = lastUse{At: *at, From: from}
		}
	}
	for _, q := range []struct{ sql, from string }{
		{`SELECT user_id, max(last_seen_at) FROM sessions GROUP BY user_id`, "a session"},
		{`SELECT principal_id, max(last_used_at) FROM api_keys WHERE last_used_at IS NOT NULL GROUP BY principal_id`, "an API key"},
		{`SELECT principal_id, max(created_at) FROM tool_invocations WHERE principal_id IS NOT NULL GROUP BY principal_id`, "a tool call"},
	} {
		rows, err := tx.Query(ctx, q.sql)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var at *time.Time
			if err := rows.Scan(&id, &at); err != nil {
				rows.Close()
				return nil, err
			}
			record(id, at, q.from)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// readUsers lists the people who are members of this workspace. The
// created time is the membership's, not the account's: what a reviewer is
// attesting to is access to this workspace, and a person who has held an
// account for three years and this workspace's access for a week is a new
// arrival here.
func readUsers(ctx context.Context, tx pgx.Tx, orgID string, use map[string]lastUse) ([]Principal, error) {
	rows, err := tx.Query(ctx, `
SELECT u.id, u.email, COALESCE(u.name, ''), m.created_at, u.disabled_at, m.deactivated_at
FROM organization_members m JOIN users u ON u.id = m.user_id
WHERE m.organization_id = $1
ORDER BY lower(u.email)`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Principal{}
	for rows.Next() {
		var (
			p                     Principal
			email, name           string
			disabled, deactivated *time.Time
		)
		if err := rows.Scan(&p.ID, &email, &name, &p.CreatedAt, &disabled, &deactivated); err != nil {
			return nil, err
		}
		p.Kind = "user"
		p.Display = email
		if name != "" {
			p.Display = email + " (" + name + ")"
		}
		switch {
		case disabled != nil:
			p.Status = "disabled"
		case deactivated != nil:
			p.Status = "deactivated"
		default:
			p.Status = "active"
		}
		applyUse(&p, use)
		out = append(out, p)
	}
	return out, rows.Err()
}

func readServiceAccounts(ctx context.Context, tx pgx.Tx, use map[string]lastUse) ([]Principal, error) {
	rows, err := tx.Query(ctx, `
SELECT id, name, client_id, scopes, COALESCE(server_id, ''), last_used_at, disabled_at, created_at
FROM service_accounts ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Principal{}
	for rows.Next() {
		var (
			p                  Principal
			name, clientID     string
			lastUsed, disabled *time.Time
		)
		if err := rows.Scan(&p.ID, &name, &clientID, &p.Scopes, &p.ServerID, &lastUsed, &disabled, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.Kind = "service_account"
		// The client id is shown because it is what an operator matches
		// against whatever holds the other half of the credential.
		p.Display = name + " (" + clientID + ")"
		p.Status = "active"
		if disabled != nil {
			p.Status = "disabled"
		}
		applyUse(&p, use)
		if lastUsed != nil && (p.LastUsed == nil || lastUsed.After(*p.LastUsed)) {
			p.LastUsed, p.LastUsedFrom = lastUsed, "client credentials"
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func readAPIKeys(ctx context.Context, tx pgx.Tx, now time.Time) ([]Principal, error) {
	rows, err := tx.Query(ctx, `
SELECT id, name, prefix, principal_kind, principal_id, scopes, COALESCE(server_id, ''),
       expires_at, last_used_at, revoked_at, created_at
FROM api_keys ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Principal{}
	for rows.Next() {
		var (
			p                 Principal
			name, prefix      string
			kind, principalID string
			lastUsed, revoked *time.Time
			expires           *time.Time
		)
		if err := rows.Scan(&p.ID, &name, &prefix, &kind, &principalID, &p.Scopes, &p.ServerID,
			&expires, &lastUsed, &revoked, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.Kind = "api_key"
		// The prefix identifies the key in a log and is not the key: the
		// secret half is stored only as a digest and never leaves.
		p.Display = name + " (" + prefix + "…)"
		p.ActsAs = kind + "|" + principalID
		p.ExpiresAt = expires
		p.LastUsed = lastUsed
		if lastUsed != nil {
			p.LastUsedFrom = "an API key"
		}
		switch {
		case revoked != nil:
			p.Status = "revoked"
		case expires != nil && expires.Before(now):
			p.Status = "expired"
		default:
			p.Status = "active"
		}
		p.Bindings = []Binding{}
		out = append(out, p)
	}
	return out, rows.Err()
}

// readGroups lists the provisioned groups a binding can name, with the
// people in each. A group binding is the one grant a reviewer cannot read
// off the principal it affects, so the membership has to be spelled out.
func readGroups(ctx context.Context, tx pgx.Tx) ([]Principal, error) {
	members := map[string][]string{}
	mrows, err := tx.Query(ctx, `
SELECT m.group_id, COALESCE(NULLIF(u.name, ''), u.email)
FROM scim_group_members m JOIN users u ON u.id = m.user_id`)
	if err != nil {
		return nil, err
	}
	for mrows.Next() {
		var group, who string
		if err := mrows.Scan(&group, &who); err != nil {
			mrows.Close()
			return nil, err
		}
		members[group] = append(members[group], who)
	}
	err = mrows.Err()
	mrows.Close()
	if err != nil {
		return nil, err
	}

	rows, err := tx.Query(ctx, `SELECT id, display_name, created_at FROM scim_groups ORDER BY display_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Principal{}
	for rows.Next() {
		var p Principal
		if err := rows.Scan(&p.ID, &p.Display, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.Kind = "idp_group"
		p.Status = "active"
		p.Members = sortedStrings(members[p.ID])
		out = append(out, p)
	}
	return out, rows.Err()
}

// readSecretRotations reads the audit stream for the one event that says
// a service account's secret was replaced. The stream is the only record
// of it: service_accounts holds the current digest and when the row was
// last touched, and "touched" covers renaming it.
func readSecretRotations(ctx context.Context, tx pgx.Tx) (map[string]time.Time, error) {
	rows, err := tx.Query(ctx, `
SELECT target_id, max(ts) FROM audit_events
WHERE action = 'service_account.rotate_secret' AND outcome = 'success'
  AND target_kind = 'service_account' AND target_id IS NOT NULL
GROUP BY target_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var at time.Time
		if err := rows.Scan(&id, &at); err != nil {
			return nil, err
		}
		out[id] = at
	}
	return out, rows.Err()
}

func applyUse(p *Principal, use map[string]lastUse) {
	if u, ok := use[p.ID]; ok {
		at := u.At
		p.LastUsed, p.LastUsedFrom = &at, u.From
	}
}
