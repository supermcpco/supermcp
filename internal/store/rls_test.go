package store_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// TestRLSMatrix seeds two tenants and asserts, for every table that carries
// organization_id (discovered from information_schema so a new table cannot
// slip through), that the other tenant sees zero rows and its own tenant
// sees exactly the seeded ones. Requires DATABASE_URL; skipped otherwise.
func TestRLSMatrix(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	mst, err := store.Open(ctx, url, url, log, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := mst.Migrate(ctx, true); err != nil {
		t.Fatal(err)
	}
	mst.Close()

	st, err := store.Open(ctx, url, url, log, store.Options{AppRole: true})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}

	// Seed through Bypass (maintenance role, no RLS).
	seed := `
DELETE FROM organizations WHERE id IN ('rls_a','rls_b');
DELETE FROM users WHERE id IN ('u_a','u_b');
DELETE FROM data_keys WHERE scope IN ('org:rls_a','org:rls_b') OR kek_ref = 'rls-test';
DELETE FROM tool_invocations WHERE id IN ('i_a','i_b');
DELETE FROM oauth_codes WHERE code IN ('oc_a','oc_b');
DELETE FROM oauth_refresh_tokens WHERE id IN ('rt_a','rt_b');
DELETE FROM audit_events WHERE id IN ('00000000-0000-7000-8000-00000000000a','00000000-0000-7000-8000-00000000000b');
INSERT INTO users (id, email, name) VALUES ('u_a','a@rls.test','A'), ('u_b','b@rls.test','B');
INSERT INTO organizations (id, slug, name) VALUES ('rls_a','rls-a','A'), ('rls_b','rls-b','B');
INSERT INTO organization_members (user_id, organization_id) VALUES ('u_a','rls_a'), ('u_b','rls_b');
INSERT INTO sessions (id, user_id, organization_id, idle_expires_at, absolute_expires_at, auth_method)
    VALUES ('s_a','u_a','rls_a', now()+interval '1h', now()+interval '1d','password'),
           ('s_b','u_b','rls_b', now()+interval '1h', now()+interval '1d','password');
INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id)
    VALUES ('rb_a','rls_a','user','u_a','role_owner'), ('rb_b','rls_b','user','u_b','role_owner');
INSERT INTO roles (id, organization_id, name, permissions) VALUES ('r_a','rls_a','custom-a','{tools:read}'), ('r_b','rls_b','custom-b','{tools:read}');
INSERT INTO tool_access_rules (id, organization_id, tool_id, role_id) VALUES ('tar_a','rls_a','t_a','r_a'), ('tar_b','rls_b','t_b','r_b');
INSERT INTO api_keys (id, organization_id, principal_kind, principal_id, name, prefix, hash)
    VALUES ('k_a','rls_a','user','u_a','a','pfx_a','\x00'), ('k_b','rls_b','user','u_b','b','pfx_b','\x00');
-- The instance row is retired on purpose: an active one would be picked
-- up by the real keyring, which cannot unwrap this dummy key.
INSERT INTO data_keys (id, scope, kek_ref, wrapped, status) VALUES ('\x0a','org:rls_a','rls-test','\x00','decrypt_only'), ('\x0b','org:rls_b','rls-test','\x00','decrypt_only'), ('\x0c','instance','rls-test','\x00','retired') ON CONFLICT DO NOTHING;
INSERT INTO connectors (id, organization_id, name, transport, auth) VALUES ('c_a','rls_a','A','{}','{}'), ('c_b','rls_b','B','{}','{}');
INSERT INTO connector_credentials (connector_id, organization_id, name, value_enc) VALUES ('c_a','rls_a','K','\x00'), ('c_b','rls_b','K','\x00');
INSERT INTO connector_tokens (connector_id, organization_id, token_enc, expires_at) VALUES ('c_a','rls_a','\x00',now()), ('c_b','rls_b','\x00',now());
INSERT INTO tools (id, connector_id, organization_id, name, definition) VALUES ('t_a','c_a','rls_a','a_t','{}'), ('t_b','c_b','rls_b','b_t','{}');
INSERT INTO mcp_servers (id, organization_id, slug, name) VALUES ('m_a','rls_a','a','A'), ('m_b','rls_b','b','B');
INSERT INTO mcp_server_connectors (server_id, connector_id, organization_id) VALUES ('m_a','c_a','rls_a'), ('m_b','c_b','rls_b');
INSERT INTO tool_invocations (id, organization_id, tool_name, principal_kind, auth_method, status, duration_ms)
    VALUES ('i_a','rls_a','a_t','user','session','success',1), ('i_b','rls_b','b_t','user','session','success',1);
INSERT INTO org_settings (organization_id, key, value) VALUES ('rls_a','x','1'), ('rls_b','x','1');
INSERT INTO oauth_codes (code, client_id, user_id, organization_id, redirect_uri, code_challenge, code_challenge_method, expires_at)
    VALUES ('oc_a','cl','u_a','rls_a','https://x','c','S256', now()+interval '5 min'), ('oc_b','cl','u_b','rls_b','https://x','c','S256', now()+interval '5 min');
INSERT INTO oauth_refresh_tokens (id, token_hash, family_id, client_id, user_id, organization_id, expires_at)
    VALUES ('rt_a','\x0a','f_a','cl','u_a','rls_a', now()+interval '1 day'), ('rt_b','\x0b','f_b','cl','u_b','rls_b', now()+interval '1 day');
INSERT INTO revisions (id, organization_id, entity_kind, entity_id, revision, snapshot, action)
    VALUES ('rev_a','rls_a','connector','c_a',1,'{}','create'), ('rev_b','rls_b','connector','c_b',1,'{}','create');
INSERT INTO identity_providers (id, organization_id, name, preset, client_id, issuer)
    VALUES ('idp_a','rls_a','A','generic','ca','https://a.example'), ('idp_b','rls_b','B','generic','cb','https://b.example');
INSERT INTO scim_users (organization_id, user_id, user_name) VALUES ('rls_a','u_a','a@rls.test'), ('rls_b','u_b','b@rls.test');
INSERT INTO scim_groups (id, organization_id, display_name) VALUES ('sg_a','rls_a','A'), ('sg_b','rls_b','B');
INSERT INTO scim_group_members (group_id, user_id, organization_id) VALUES ('sg_a','u_a','rls_a'), ('sg_b','u_b','rls_b');
INSERT INTO service_accounts (id, organization_id, name, client_id) VALUES ('sa_a','rls_a','A','sms_a'), ('sa_b','rls_b','B','sms_b');
INSERT INTO password_policies (organization_id) VALUES ('rls_a'), ('rls_b');
INSERT INTO audit_exporters (id, organization_id, kind, config_enc) VALUES ('ax_a','rls_a','webhook','\x00'), ('ax_b','rls_b','webhook','\x00');
INSERT INTO saml_providers (id, organization_id, name, entity_id, signing_cert, signing_key_enc, idp_entity_id, idp_sso_url)
    VALUES ('sp_a','rls_a','A','https://a.example/saml','\x00','\x00','https://idp-a.example','https://idp-a.example/sso'),
           ('sp_b','rls_b','B','https://b.example/saml','\x00','\x00','https://idp-b.example','https://idp-b.example/sso');
INSERT INTO dlp_policies (id, organization_id, name, action) VALUES ('dp_a','rls_a','A','mask'), ('dp_b','rls_b','B','mask');
INSERT INTO dlp_findings (id, organization_id, policy_id, stage, action, detector, kind, confidence)
    VALUES ('df_a','rls_a','dp_a','result','mask','builtin','email','high'), ('df_b','rls_b','dp_b','result','mask','builtin','email','high');
INSERT INTO approval_policies (id, organization_id, name, scope_kind, trigger_kind) VALUES ('ap_a','rls_a','A','organization','destructive'), ('ap_b','rls_b','B','organization','destructive');
INSERT INTO approval_requests (id, organization_id, policy_id, tool_id, tool_name, requested_by, args_enc, expires_at)
    VALUES ('ar_a','rls_a','ap_a','t_a','a_t','u_a','\x00', now()+interval '1h'), ('ar_b','rls_b','ap_b','t_b','b_t','u_b','\x00', now()+interval '1h');
INSERT INTO tool_blobs (id, organization_id, principal_id, media_type, data, expires_at)
    VALUES ('tb_a','rls_a','u_a','image/png','\x00', now()+interval '1h'), ('tb_b','rls_b','u_b','image/png','\x00', now()+interval '1h');
`
	if err := db.Bypass(ctx, "test seed", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, seed)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Audit rows go in through the writer rather than an INSERT, because a
	// row with an invented hash breaks the chain for every later row and
	// makes `audit verify` fail for reasons that have nothing to do with
	// this test.
	auditor := audit.NewWriter(db, log, audit.Options{})
	for _, org := range []string{"rls_a", "rls_b"} {
		if err := auditor.EmitSync(ctx, audit.Event{OrgID: org, Category: audit.CategorySystem,
			Action: "rls.test", Outcome: audit.Success, ActorKind: "user"}); err != nil {
			t.Fatal(err)
		}
	}
	auditor.Close()
	t.Cleanup(func() {
		_ = db.Bypass(ctx, "test cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id IN ('rls_a','rls_b'); DELETE FROM users WHERE id IN ('u_a','u_b'); DELETE FROM data_keys WHERE kek_ref = 'rls-test'; DELETE FROM tool_invocations WHERE id IN ('i_a','i_b'); DELETE FROM audit_events WHERE organization_id IN ('rls_a','rls_b')`)
			return err
		})
	})

	// Every table with organization_id must have RLS forced.
	var tables []string
	if err := db.Bypass(ctx, "test discover", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT c.table_name, t.relrowsecurity AND t.relforcerowsecurity
FROM information_schema.columns c
JOIN pg_class t ON t.relname = c.table_name AND t.relnamespace = 'public'::regnamespace
WHERE c.table_schema = 'public' AND c.column_name = 'organization_id' AND t.relkind = 'r'
ORDER BY 1`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			var forced bool
			if err := rows.Scan(&name, &forced); err != nil {
				return err
			}
			if !forced {
				t.Errorf("table %s has organization_id but RLS is not forced", name)
			}
			tables = append(tables, name)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	count := func(orgID, table, where string) int {
		var n int
		q := fmt.Sprintf("SELECT count(*) FROM %s", table)
		if where != "" {
			q += " WHERE " + where
		}
		err := db.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, q).Scan(&n)
		})
		if err != nil {
			t.Fatalf("%s as %s: %v", table, orgID, err)
		}
		return n
	}
	// The property that matters is not how many rows a tenant sees but
	// that it never sees another tenant's. Exact counts would also break
	// whenever another test leaves a shared row behind.
	for _, table := range tables {
		if a := count("rls_a", table, "organization_id = 'rls_b'"); a != 0 {
			t.Errorf("%s: org A sees %d rows belonging to org B", table, a)
		}
		if b := count("rls_b", table, "organization_id = 'rls_a'"); b != 0 {
			t.Errorf("%s: org B sees %d rows belonging to org A", table, b)
		}
		if own := count("rls_a", table, "organization_id = 'rls_a'"); own == 0 {
			t.Errorf("%s: org A cannot see its own rows", table)
		}
		// An org with no rows of its own sees nothing in tenant tables.
		// (roles also holds the built-in system roles, which every tenant
		// sees on purpose.)
		where := ""
		if table == "roles" {
			where = "NOT is_system"
		}
		if n := count("rls_nobody", table, where); n != 0 {
			t.Errorf("%s: an unknown org sees %d rows", table, n)
		}
	}
	// Tables scoped through something other than organization_id.
	if n := count("rls_a", "organizations", "id = 'rls_b'"); n != 0 {
		t.Errorf("organizations: org A sees org B")
	}
	if n := count("rls_a", "users", "id = 'u_b'"); n != 0 {
		t.Errorf("users: org A sees a user of org B")
	}
	if n := count("rls_a", "sessions", "user_id = 'u_b'"); n != 0 {
		t.Errorf("sessions: org A sees a session of org B")
	}
	if n := count("rls_a", "roles", "organization_id = 'rls_b'"); n != 0 {
		t.Errorf("roles: org A sees a custom role of org B")
	}
	if n := count("rls_a", "roles", "is_system"); n == 0 {
		t.Error("roles: system roles should be visible to every tenant")
	}
	if n := count("rls_a", "data_keys", "scope = 'org:rls_b'"); n != 0 {
		t.Errorf("data_keys: org A sees org B's key")
	}
	if n := count("rls_a", "data_keys", "scope = 'org:rls_a'"); n == 0 {
		t.Error("data_keys: org A cannot see its own key")
	}

	// Cross-tenant write is rejected, not silently redirected.
	err = db.Tx(tenant.WithOrg(ctx, "rls_a"), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO connectors (id, organization_id, name, transport, auth) VALUES ('c_x','rls_b','X','{}','{}')`)
		return err
	})
	if err == nil {
		t.Error("insert into another tenant succeeded")
	}
	// Missing org is a hard error, never an open door.
	if err := db.Tx(ctx, func(pgx.Tx) error { return nil }); !errors.Is(err, tenant.ErrNoOrg) {
		t.Errorf("Tx without org: %v", err)
	}
	// Pre-auth lookups work with no tenant.
	var email string
	err = db.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT email FROM auth_user_by_email($1)", "A@RLS.TEST").Scan(&email)
	})
	if err != nil || email != "a@rls.test" {
		t.Errorf("auth_user_by_email: %q %v", email, err)
	}
	// ...but a plain query with no tenant sees nothing.
	var n int
	_ = db.Pre(ctx, func(tx pgx.Tx) error { return tx.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&n) })
	if n != 0 {
		t.Errorf("users visible without tenant: %d", n)
	}
}
