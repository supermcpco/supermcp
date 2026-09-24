-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Roles. The application pool switches to supermcp_app on every connection
-- (SET ROLE), so row-level security applies even when the login user owns
-- the schema. Migrations and maintenance jobs run as the login user.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'supermcp_app') THEN
        CREATE ROLE supermcp_app NOLOGIN NOBYPASSRLS NOINHERIT;
    END IF;
END $$;
GRANT supermcp_app TO CURRENT_USER;
GRANT USAGE ON SCHEMA public TO supermcp_app;

-- ---------------------------------------------------------------------------
-- Identity

CREATE TABLE users (
    id              text PRIMARY KEY,
    email           text NOT NULL,
    email_lower     text GENERATED ALWAYS AS (lower(email)) STORED,
    name            text NOT NULL DEFAULT '',
    password_hash   text,
    disabled_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_lower_idx ON users (email_lower);

CREATE TABLE organizations (
    id          text PRIMARY KEY,
    slug        text NOT NULL UNIQUE,
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE organization_members (
    user_id         text NOT NULL REFERENCES users ON DELETE CASCADE,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    deactivated_at  timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, organization_id)
);
CREATE INDEX organization_members_org_idx ON organization_members (organization_id);

CREATE TABLE sessions (
    id                  text PRIMARY KEY,
    user_id             text NOT NULL REFERENCES users ON DELETE CASCADE,
    organization_id     text REFERENCES organizations ON DELETE SET NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz NOT NULL DEFAULT now(),
    idle_expires_at     timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    mfa_verified_at     timestamptz,
    auth_method         text NOT NULL,
    ip                  inet,
    user_agent          text,
    revoked_at          timestamptz,
    revoked_reason      text
);
CREATE INDEX sessions_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_idle_idx ON sessions (idle_expires_at);

CREATE TABLE login_lockouts (
    key          text PRIMARY KEY,
    failures     int NOT NULL DEFAULT 0,
    locked_until timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Authorization

CREATE TABLE roles (
    id              text PRIMARY KEY,
    organization_id text REFERENCES organizations ON DELETE CASCADE, -- NULL only for is_system
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    is_system       boolean NOT NULL DEFAULT false,
    permissions     text[] NOT NULL DEFAULT '{}',
    revision        int NOT NULL DEFAULT 1,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX roles_org_name_idx ON roles (COALESCE(organization_id, ''), name);

CREATE TABLE role_bindings (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    principal_kind  text NOT NULL CHECK (principal_kind IN ('user', 'service_account', 'idp_group')),
    principal_id    text NOT NULL,
    role_id         text NOT NULL REFERENCES roles ON DELETE CASCADE,
    scope_kind      text NOT NULL DEFAULT 'org' CHECK (scope_kind IN ('org', 'server', 'connector', 'tool')),
    scope_id        text,
    source          text NOT NULL DEFAULT 'manual',
    external_ref    text,
    expires_at      timestamptz,
    created_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, principal_kind, principal_id, role_id, scope_kind, scope_id, source)
);
CREATE INDEX role_bindings_principal_idx ON role_bindings (organization_id, principal_kind, principal_id);

CREATE TABLE tool_access_rules (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    tool_id         text NOT NULL,
    role_id         text NOT NULL REFERENCES roles ON DELETE CASCADE,
    effect          text NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow', 'deny')),
    UNIQUE (tool_id, role_id, effect)
);

CREATE TABLE api_keys (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    principal_kind  text NOT NULL CHECK (principal_kind IN ('user', 'service_account')),
    principal_id    text NOT NULL,
    name            text NOT NULL,
    prefix          text NOT NULL,
    hash            bytea NOT NULL,
    scopes          text[] NOT NULL DEFAULT '{}',
    server_id       text,
    expires_at      timestamptz,
    last_used_at    timestamptz,
    last_used_ip    inet,
    rotated_from    text REFERENCES api_keys ON DELETE SET NULL,
    revoked_at      timestamptz,
    revoked_reason  text,
    created_by      text,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX api_keys_prefix_idx ON api_keys (prefix) WHERE revoked_at IS NULL;
CREATE INDEX api_keys_org_idx ON api_keys (organization_id);

-- ---------------------------------------------------------------------------
-- Secrets

CREATE TABLE kek_configs (
    id          text PRIMARY KEY,
    ref         text NOT NULL UNIQUE,
    status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retiring', 'retired')),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE data_keys (
    id          bytea PRIMARY KEY,
    scope       text NOT NULL,
    kek_ref     text NOT NULL,
    wrapped     bytea NOT NULL,
    status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'decrypt_only', 'retired')),
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX data_keys_active_scope_idx ON data_keys (scope) WHERE status = 'active';

-- ---------------------------------------------------------------------------
-- Connectors, tools, servers

CREATE TABLE connectors (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    name            text NOT NULL,
    transport       jsonb NOT NULL,          -- adapter.Transport (no secrets)
    auth            jsonb NOT NULL,          -- adapter.Auth with {{env.*}} placeholders only
    instructions    text NOT NULL DEFAULT '',
    catalog_slug    text,
    catalog_hash    text,
    read_only       boolean NOT NULL DEFAULT true,
    enabled         boolean NOT NULL DEFAULT true,
    version         bigint NOT NULL DEFAULT 1,
    created_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX connectors_org_idx ON connectors (organization_id);

-- One row per credential; the name is visible, the value is sealed.
CREATE TABLE connector_credentials (
    connector_id    text NOT NULL REFERENCES connectors ON DELETE CASCADE,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    name            text NOT NULL,
    value_enc       bytea NOT NULL,
    secret          boolean NOT NULL DEFAULT true,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (connector_id, name)
);

-- Upstream tokens obtained at runtime (OAuth2 access/refresh, login sessions).
CREATE TABLE connector_tokens (
    connector_id    text PRIMARY KEY REFERENCES connectors ON DELETE CASCADE,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    token_enc       bytea NOT NULL,
    expires_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tools (
    id              text PRIMARY KEY,
    connector_id    text NOT NULL REFERENCES connectors ON DELETE CASCADE,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    name            text NOT NULL,
    definition      jsonb NOT NULL,          -- adapter.Tool
    operation_id    text,
    enabled         boolean NOT NULL DEFAULT true,
    deprecated_at   timestamptz,
    version         bigint NOT NULL DEFAULT 1,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (connector_id, name)
);
CREATE INDEX tools_org_idx ON tools (organization_id);

CREATE TABLE mcp_servers (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    slug            text NOT NULL,
    name            text NOT NULL,
    instructions    text NOT NULL DEFAULT '',
    enabled         boolean NOT NULL DEFAULT true,
    version         bigint NOT NULL DEFAULT 1,
    created_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, slug)
);

CREATE TABLE mcp_server_connectors (
    server_id       text NOT NULL REFERENCES mcp_servers ON DELETE CASCADE,
    connector_id    text NOT NULL REFERENCES connectors ON DELETE CASCADE,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    PRIMARY KEY (server_id, connector_id)
);

CREATE TABLE tool_invocations (
    id              text PRIMARY KEY,
    organization_id text NOT NULL,
    server_id       text,
    connector_id    text,
    tool_id         text,
    tool_name       text NOT NULL,
    principal_kind  text NOT NULL,
    principal_id    text,
    auth_method     text NOT NULL,
    status          text NOT NULL CHECK (status IN ('success', 'error', 'timeout', 'denied')),
    duration_ms     int NOT NULL,
    upstream_ms     int,
    input           jsonb,
    output          jsonb,
    error           text,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tool_invocations_org_time_idx ON tool_invocations (organization_id, created_at DESC);
CREATE INDEX tool_invocations_tool_time_idx ON tool_invocations (tool_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Settings

CREATE TABLE site_settings (
    key         text PRIMARY KEY,
    value       jsonb NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE org_settings (
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    key             text NOT NULL,
    value           jsonb NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, key)
);

-- ---------------------------------------------------------------------------
-- Row-level security. The current tenant is the transaction-local setting
-- app.current_org; a missing setting matches nothing (fail closed).

CREATE OR REPLACE FUNCTION current_org() RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE AS $f$
    SELECT NULLIF(current_setting('app.current_org', true), '')
$f$;

-- Tables keyed directly by organization_id.
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'organization_members', 'role_bindings', 'tool_access_rules', 'api_keys',
        'connectors', 'connector_credentials', 'connector_tokens', 'tools',
        'mcp_servers', 'mcp_server_connectors', 'tool_invocations', 'org_settings'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY org_isolation ON %I USING (organization_id = current_org()) WITH CHECK (organization_id = current_org())', t);
    END LOOP;
END $$;

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON organizations USING (id = current_org()) WITH CHECK (id = current_org());

-- System roles are visible to every tenant; custom roles only to their own.
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON roles
    USING (is_system OR organization_id = current_org())
    WITH CHECK (NOT is_system AND organization_id = current_org());

-- Data keys: the tenant's own scope plus the instance scope.
ALTER TABLE data_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE data_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON data_keys
    USING (scope = 'instance' OR scope = 'org:' || current_org())
    WITH CHECK (scope = 'instance' OR scope = 'org:' || current_org());

-- Users are cross-tenant; a tenant sees its members only.
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON users
    USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.user_id = users.id AND m.organization_id = current_org()));

-- Sessions belong to users; visible through membership in the current org.
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON sessions
    USING (EXISTS (SELECT 1 FROM organization_members m WHERE m.user_id = sessions.user_id AND m.organization_id = current_org()))
    WITH CHECK (EXISTS (SELECT 1 FROM organization_members m WHERE m.user_id = sessions.user_id AND m.organization_id = current_org()));

-- Instance-level tables are not tenant-scoped; the app role may read them,
-- and only site settings are writable.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO supermcp_app;
REVOKE INSERT, UPDATE, DELETE ON login_lockouts, kek_configs, goose_db_version, instance FROM supermcp_app;
GRANT INSERT, UPDATE ON login_lockouts TO supermcp_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO supermcp_app;

-- ---------------------------------------------------------------------------
-- Pre-authentication lookups run before a tenant is known. Each is a
-- SECURITY DEFINER function with a fixed, narrow shape instead of a wider
-- table policy.

CREATE OR REPLACE FUNCTION auth_user_by_email(p_email text)
RETURNS TABLE (id text, email text, name text, password_hash text, disabled_at timestamptz)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT u.id, u.email, u.name, u.password_hash, u.disabled_at
    FROM users u WHERE u.email_lower = lower(p_email)
$f$;

CREATE OR REPLACE FUNCTION auth_session(p_id text)
RETURNS TABLE (id text, user_id text, organization_id text, idle_expires_at timestamptz, absolute_expires_at timestamptz,
               mfa_verified_at timestamptz, auth_method text, revoked_at timestamptz, last_seen_at timestamptz)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT s.id, s.user_id, s.organization_id, s.idle_expires_at, s.absolute_expires_at,
           s.mfa_verified_at, s.auth_method, s.revoked_at, s.last_seen_at
    FROM sessions s WHERE s.id = p_id
$f$;

CREATE OR REPLACE FUNCTION auth_api_key(p_prefix text)
RETURNS TABLE (id text, organization_id text, principal_kind text, principal_id text, hash bytea, scopes text[],
               server_id text, expires_at timestamptz, revoked_at timestamptz)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT k.id, k.organization_id, k.principal_kind, k.principal_id, k.hash, k.scopes,
           k.server_id, k.expires_at, k.revoked_at
    FROM api_keys k WHERE k.prefix = p_prefix AND k.revoked_at IS NULL
$f$;

-- Memberships of a user across tenants, for the org switcher.
CREATE OR REPLACE FUNCTION auth_user_orgs(p_user_id text)
RETURNS TABLE (organization_id text, slug text, name text)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT o.id, o.slug, o.name
    FROM organization_members m JOIN organizations o ON o.id = m.organization_id
    WHERE m.user_id = p_user_id AND m.deactivated_at IS NULL
$f$;

-- Session bookkeeping that runs before the tenant is set.
CREATE OR REPLACE FUNCTION auth_session_create(p_id text, p_user_id text, p_org text, p_idle timestamptz, p_abs timestamptz,
                                               p_method text, p_ip inet, p_ua text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    INSERT INTO sessions (id, user_id, organization_id, idle_expires_at, absolute_expires_at, auth_method, ip, user_agent)
    VALUES (p_id, p_user_id, p_org, p_idle, p_abs, p_method, p_ip, p_ua)
$f$;

CREATE OR REPLACE FUNCTION auth_session_touch(p_id text, p_idle timestamptz, p_org text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    UPDATE sessions SET last_seen_at = now(), idle_expires_at = p_idle, organization_id = COALESCE(p_org, organization_id)
    WHERE id = p_id
$f$;

CREATE OR REPLACE FUNCTION auth_session_revoke(p_id text, p_reason text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason WHERE id = p_id AND revoked_at IS NULL
$f$;

-- First-run bootstrap: the very first user creates the first organization.
CREATE OR REPLACE FUNCTION auth_user_count()
RETURNS bigint LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT count(*) FROM users
$f$;

CREATE OR REPLACE FUNCTION auth_register(p_user_id text, p_email text, p_name text, p_password_hash text,
                                         p_org_id text, p_org_slug text, p_org_name text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
BEGIN
    INSERT INTO users (id, email, name, password_hash) VALUES (p_user_id, p_email, p_name, p_password_hash);
    IF p_org_id IS NOT NULL THEN
        INSERT INTO organizations (id, slug, name) VALUES (p_org_id, p_org_slug, p_org_name);
        INSERT INTO organization_members (user_id, organization_id) VALUES (p_user_id, p_org_id);
    END IF;
END
$f$;

REVOKE ALL ON FUNCTION auth_user_by_email(text), auth_session(text), auth_api_key(text), auth_user_orgs(text),
    auth_session_create(text, text, text, timestamptz, timestamptz, text, inet, text),
    auth_session_touch(text, timestamptz, text), auth_session_revoke(text, text), auth_user_count(),
    auth_register(text, text, text, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_user_by_email(text), auth_session(text), auth_api_key(text), auth_user_orgs(text),
    auth_session_create(text, text, text, timestamptz, timestamptz, text, inet, text),
    auth_session_touch(text, timestamptz, text), auth_session_revoke(text, text), auth_user_count(),
    auth_register(text, text, text, text, text, text, text) TO supermcp_app;

-- ---------------------------------------------------------------------------
-- Built-in roles.
INSERT INTO roles (id, organization_id, name, description, is_system, permissions) VALUES
    ('role_owner',    NULL, 'owner',    'Full control of the organization', true, ARRAY['*']),
    ('role_admin',    NULL, 'admin',    'Everything except deleting the organization and billing', true,
        ARRAY['org:read','org:update','org:members:manage','org:settings:manage',
              'connectors:read','connectors:create','connectors:update','connectors:delete','connectors:auth:update','connectors:test',
              'tools:read','tools:update','tools:invoke','tools:invoke:destructive',
              'servers:read','servers:create','servers:update','servers:delete',
              'roles:read','roles:manage','apikeys:self:manage','apikeys:org:manage','serviceaccounts:manage',
              'idp:manage','scim:manage','audit:read','audit:export','audit:policy:manage',
              'approvals:request','approvals:decide','dlp:manage','revisions:rollback','secrets:rotate']),
    ('role_editor',   NULL, 'editor',   'Create and edit connectors, tools and servers', true,
        ARRAY['org:read','connectors:read','connectors:create','connectors:update','connectors:delete','connectors:test',
              'tools:read','tools:update','tools:invoke','servers:read','servers:create','servers:update','servers:delete',
              'roles:read','apikeys:self:manage','approvals:request']),
    ('role_viewer',   NULL, 'viewer',   'Read everything, invoke tools', true,
        ARRAY['org:read','connectors:read','tools:read','tools:invoke','servers:read','roles:read','apikeys:self:manage']),
    ('role_approver', NULL, 'approver', 'Viewer plus deciding approvals', true,
        ARRAY['org:read','connectors:read','tools:read','tools:invoke','servers:read','roles:read','apikeys:self:manage','approvals:decide']),
    ('role_auditor',  NULL, 'auditor',  'Read everything including the audit trail', true,
        ARRAY['org:read','connectors:read','tools:read','servers:read','roles:read','audit:read','audit:export']),
    ('role_mcp_consumer', NULL, 'mcp-consumer', 'Invoke tools only', true,
        ARRAY['tools:read','tools:invoke']);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS auth_register(text, text, text, text, text, text, text), auth_user_count(), auth_session_revoke(text, text),
    auth_session_touch(text, timestamptz, text), auth_session_create(text, text, text, timestamptz, timestamptz, text, inet, text),
    auth_user_orgs(text), auth_api_key(text), auth_session(text), auth_user_by_email(text), current_org();
DROP TABLE IF EXISTS org_settings, site_settings, tool_invocations, mcp_server_connectors, mcp_servers, tools,
    connector_tokens, connector_credentials, connectors, data_keys, kek_configs, api_keys, tool_access_rules,
    role_bindings, roles, login_lockouts, sessions, organization_members, organizations, users;
-- +goose StatementEnd
