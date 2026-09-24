package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
)

// ExportOptions tunes a subject access export.
type ExportOptions struct {
	// Audit records that one person's record was read out. An export is a
	// privileged read of personal data and belongs in the stream like any
	// other. Nil skips it.
	Audit Recorder
}

// Export is everything this instance holds about one person, in the form
// it is handed over.
type Export struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Subject     Subject   `json:"subject"`
	// Files is what the export contains, in the order it is written.
	Files []ExportFile `json:"files"`
	// Excluded says what this instance holds about the person that is
	// deliberately not in the export, and why. An export that quietly
	// omitted something would be a worse answer than one that says so.
	Excluded []Untouched `json:"excluded"`
}

// ExportFile is one file of the export.
type ExportFile struct {
	Name string `json:"name"`
	// About says in one line what the file holds, for a person who did not
	// ask for a database.
	About   string `json:"about"`
	Records int    `json:"records"`
	// Bytes is the file's content. It is not serialised into the manifest;
	// it is what the writer writes.
	Bytes []byte `json:"-"`
}

// BuildExport gathers the subject's record.
//
// Every query names the subject's own id. Nothing here is filtered by
// workspace, because a person's record is not owned by one, and nothing
// here returns a row that is not about them: an export that leaked one
// other person's data would be a breach committed in the course of
// answering a request about privacy.
func BuildExport(ctx context.Context, d Deps, s *Subject, opts ExportOptions) (*Export, error) {
	now := d.now()
	ex := &Export{GeneratedAt: now, Subject: *s}

	type source struct {
		name, about, sql string
	}
	sources := []source{
		{"memberships.json", "the workspaces this account belongs to", `
SELECT json_build_object('organizationId', m.organization_id, 'slug', o.slug, 'name', o.name,
    'joinedAt', m.created_at, 'deactivatedAt', m.deactivated_at)
FROM organization_members m JOIN organizations o ON o.id = m.organization_id
WHERE m.user_id = $1 ORDER BY o.slug`},

		{"role-bindings.json", "the roles this account holds, and where each one applies", `
SELECT json_build_object('id', b.id, 'organizationId', b.organization_id, 'role', r.name,
    'permissions', r.permissions, 'scopeKind', b.scope_kind, 'scopeId', b.scope_id,
    'source', b.source, 'expiresAt', b.expires_at, 'grantedAt', b.created_at)
FROM role_bindings b JOIN roles r ON r.id = b.role_id
WHERE b.principal_kind = 'user' AND b.principal_id = $1 ORDER BY b.created_at`},

		{"identities.json", "the single sign-on accounts linked to this one", `
SELECT json_build_object('provider', p.name, 'organizationId', p.organization_id, 'preset', p.preset,
    'subject', i.subject, 'email', i.email, 'linkedAt', i.created_at, 'lastLoginAt', i.last_login_at)
FROM user_identities i JOIN identity_providers p ON p.id = i.idp_id
WHERE i.user_id = $1 ORDER BY i.created_at`},

		{"provisioning.json", "what a provisioning system sent about this account", `
SELECT json_build_object('organizationId', organization_id, 'userName', user_name, 'externalId', external_id,
    'active', active, 'raw', raw, 'createdAt', created_at, 'updatedAt', updated_at)
FROM scim_users WHERE user_id = $1 ORDER BY organization_id`},

		{"sessions.json", "every sign-in session, live and ended", `
SELECT json_build_object('organizationId', organization_id, 'createdAt', created_at, 'lastSeenAt', last_seen_at,
    'idleExpiresAt', idle_expires_at, 'absoluteExpiresAt', absolute_expires_at, 'mfaVerifiedAt', mfa_verified_at,
    'authMethod', auth_method, 'ip', host(ip), 'userAgent', user_agent,
    'revokedAt', revoked_at, 'revokedReason', revoked_reason)
FROM sessions WHERE user_id = $1 ORDER BY created_at`},

		{"api-keys.json", "the API keys issued to this account; the keys themselves are stored as digests and are not here", `
SELECT json_build_object('id', id, 'organizationId', organization_id, 'name', name, 'prefix', prefix,
    'scopes', scopes, 'serverId', server_id, 'expiresAt', expires_at, 'lastUsedAt', last_used_at,
    'lastUsedIp', host(last_used_ip), 'revokedAt', revoked_at, 'revokedReason', revoked_reason, 'createdAt', created_at)
FROM api_keys WHERE principal_kind = 'user' AND principal_id = $1 ORDER BY created_at`},

		{"oauth-tokens.json", "the OAuth refresh tokens issued for this account; the tokens are stored as digests and are not here", `
SELECT json_build_object('id', id, 'organizationId', organization_id, 'clientId', client_id, 'serverId', server_id,
    'scope', scope, 'expiresAt', expires_at, 'consumedAt', consumed_at, 'revokedAt', revoked_at, 'createdAt', created_at)
FROM oauth_refresh_tokens WHERE user_id = $1 ORDER BY created_at`},

		{"tool-calls.json", "the tool calls this account made; what is kept of the arguments is decided by the workspace's payload policy", `
SELECT json_build_object('id', id, 'organizationId', organization_id, 'serverId', server_id,
    'connectorId', connector_id, 'tool', tool_name, 'authMethod', auth_method, 'status', status,
    'durationMs', duration_ms, 'input', input, 'output', output, 'error', error, 'at', created_at)
FROM tool_invocations WHERE principal_id = $1 ORDER BY created_at`},

		{"approvals.json", "approvals this account raised or decided; the sealed arguments are not opened here", `
SELECT json_build_object('id', id, 'organizationId', organization_id, 'policy', policy_name, 'tool', tool_name,
    'requestedBy', requested_by, 'requesterDisplay', requester_display, 'state', state,
    'decidedBy', decided_by, 'decidedAt', decided_at, 'reason', reason, 'createdAt', created_at)
FROM approval_requests WHERE requested_by = $1 OR decided_by = $1 ORDER BY created_at`},

		{"configuration-changes.json", "configuration changes this account made", `
SELECT json_build_object('id', id, 'organizationId', organization_id, 'kind', entity_kind, 'entityId', entity_id,
    'revision', revision, 'action', action, 'diff', diff, 'at', created_at)
FROM revisions WHERE actor_id = $1 ORDER BY created_at`},

		{"audit-events.json", "every audit event naming this account, as the actor, the target, or the person an OAuth client acted for", `
SELECT json_build_object('id', id, 'at', ts, 'organizationId', organization_id, 'category', category,
    'action', action, 'outcome', outcome, 'actorKind', actor_kind, 'actorId', actor_id, 'actorDisplay', actor_display,
    'targetKind', target_kind, 'targetId', target_id, 'targetDisplay', target_display,
    'ip', host(ip), 'userAgent', user_agent, 'diff', diff, 'payload', payload, 'meta', meta)
FROM audit_events WHERE actor_id = $1 OR target_id = $1 OR on_behalf_of = $1 ORDER BY seq`},
	}

	account, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	ex.Files = []ExportFile{{Name: "subject.json", About: "the account itself", Records: 1, Bytes: append(account, '\n')}}

	err = d.DB.Bypass(ctx,
		"compliance:dsar-export gathers one person's record from every workspace they belong to and from the audit stream, "+
			"which belongs to no tenant",
		func(tx pgx.Tx) error {
			ex.Files = ex.Files[:1]
			for _, src := range sources {
				rows, n, err := jsonRows(ctx, tx, src.sql, s.UserID)
				if err != nil {
					return fmt.Errorf("gather %s: %w", src.name, err)
				}
				ex.Files = append(ex.Files, ExportFile{Name: src.name, About: src.about, Records: n, Bytes: rows})
			}
			return nil
		})
	if err != nil {
		return nil, err
	}

	ex.Excluded = []Untouched{
		{Where: "users.password_hash, password_history.hash", Rows: -1,
			Why: "argon2id digests of passwords. They are not readable and handing them over would be handing over material " +
				"somebody could attack offline."},
		{Where: "api_keys.hash, oauth_refresh_tokens.token_hash, service_accounts.secret_hash", Rows: -1,
			Why: "the digests of bearer credentials. The metadata of every key is in the export; the key is not, and cannot be recovered."},
		{Where: "sessions.id", Rows: -1,
			Why: "a session is held by the digest of the cookie's secret, and the row's id is that digest. It identifies nothing " +
				"about the person and would be a live credential's key if it were handed out."},
		{Where: "approval_requests.args_enc", Rows: -1,
			Why: "the arguments sealed when an approval was raised. They are encrypted under the workspace's data key and are not " +
				"opened by this command; ask the workspace for them if they are needed."},
		{Where: "audit events naming this person only in a diff", Rows: -1,
			Why: "an event whose actor and target are somebody else, and whose diff mentions this person, is that other person's " +
				"record as much as this one's. It is not exported, because a subject access request is not a way to read a colleague's."},
	}

	if opts.Audit != nil {
		if err := recordExport(ctx, opts.Audit, ex); err != nil {
			return ex, fmt.Errorf("the export was built but could not be recorded in the audit stream: %w", err)
		}
	}
	return ex, nil
}

// jsonRows runs a query whose single column is a JSON object per row and
// returns a JSON array of them. Building the objects in Postgres rather
// than in Go keeps the export's shape next to the query that decides it,
// and keeps one struct per table out of a package that does not otherwise
// need them.
func jsonRows(ctx context.Context, tx pgx.Tx, sql, userID string) ([]byte, int, error) {
	rows, err := tx.Query(ctx, sql, userID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []byte("[\n")
	n := 0
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		if n > 0 {
			out = append(out, ',', '\n')
		}
		out = append(out, ' ', ' ')
		out = append(out, indentJSON(raw)...)
		n++
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return append(out, '\n', ']', '\n'), n, nil
}

// indentJSON re-indents one row so the file is readable by the person it
// is about, who did not ask for one very long line.
func indentJSON(raw []byte) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	b, err := json.MarshalIndent(v, "  ", "  ")
	if err != nil {
		return raw
	}
	return b
}

func recordExport(ctx context.Context, rec Recorder, ex *Export) error {
	records := 0
	for _, f := range ex.Files {
		records += f.Records
	}
	orgs := map[string]bool{}
	for _, f := range ex.Files {
		if f.Name == "memberships.json" {
			// The workspaces are already in the export; reading them back
			// from it keeps this function from running an eleventh query.
			var list []struct {
				OrganizationID string `json:"organizationId"`
			}
			if err := json.Unmarshal(f.Bytes, &list); err == nil {
				for _, m := range list {
					orgs[m.OrganizationID] = true
				}
			}
		}
	}
	ids := make([]string, 0, len(orgs))
	for id := range orgs {
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		ids = append(ids, "")
	}
	for _, org := range sortedStrings(ids) {
		if err := rec.EmitSync(ctx, audit.Event{
			OrgID: org, Category: audit.CategoryAdmin, Action: "dsar.export", Outcome: audit.Success,
			ActorKind: "system", ActorDisplay: "supermcp dsar export",
			TargetKind: "user", TargetID: ex.Subject.UserID, TargetDisplay: ex.Subject.Email,
			Meta: map[string]any{"records": records, "files": len(ex.Files),
				"reason": "subject access request"},
		}); err != nil {
			return err
		}
	}
	return nil
}
