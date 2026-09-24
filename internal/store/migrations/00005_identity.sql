-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Single sign-on
--
-- One row per identity provider per organisation. The client secret is
-- sealed with the organisation's data key; the discovery document is cached
-- here so a sign-in does not depend on reaching the provider's metadata
-- endpoint first.
CREATE TABLE identity_providers (
    id                     text PRIMARY KEY,
    organization_id        text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    name                   text NOT NULL,
    preset                 text NOT NULL CHECK (preset IN ('entra', 'google', 'okta', 'auth0', 'github', 'generic')),
    protocol               text NOT NULL DEFAULT 'oidc' CHECK (protocol IN ('oidc', 'oauth2')),
    issuer                 text NOT NULL DEFAULT '',
    client_id              text NOT NULL,
    client_secret_enc      bytea,
    scopes                 text[] NOT NULL DEFAULT '{}',
    -- Cached discovery. Refreshed lazily; a generic provider may also have
    -- these set by hand when it publishes no metadata document.
    authorization_endpoint text NOT NULL DEFAULT '',
    token_endpoint         text NOT NULL DEFAULT '',
    userinfo_endpoint      text NOT NULL DEFAULT '',
    jwks_uri               text NOT NULL DEFAULT '',
    discovered_at          timestamptz,
    -- Who may sign in, and what they get.
    allowed_domains        text[] NOT NULL DEFAULT '{}',
    jit_provisioning       boolean NOT NULL DEFAULT true,
    default_role_id        text REFERENCES roles ON DELETE SET NULL,
    groups_claim           text NOT NULL DEFAULT '',
    enabled                boolean NOT NULL DEFAULT true,
    created_by             text,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX identity_providers_org_idx ON identity_providers (organization_id);

-- A sign-in in flight. Holds the state, the nonce and the PKCE verifier,
-- which must not live in a cookie the provider's redirect can influence.
CREATE TABLE sso_requests (
    state          text PRIMARY KEY,
    idp_id         text NOT NULL REFERENCES identity_providers ON DELETE CASCADE,
    nonce          text NOT NULL,
    code_verifier  text NOT NULL,
    redirect_after text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz
);
CREATE INDEX sso_requests_expiry_idx ON sso_requests (expires_at);

-- The link between a provider's subject and our user. The subject, not the
-- email address, is the identity: an address can be reassigned.
CREATE TABLE user_identities (
    idp_id        text NOT NULL REFERENCES identity_providers ON DELETE CASCADE,
    subject       text NOT NULL,
    user_id       text NOT NULL REFERENCES users ON DELETE CASCADE,
    email         text NOT NULL DEFAULT '',
    last_login_at timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (idp_id, subject)
);
CREATE INDEX user_identities_user_idx ON user_identities (user_id);

-- ---------------------------------------------------------------------------
-- SCIM provisioning
--
-- The provisioning system's own identifier for a user or group, kept beside
-- ours so a later PATCH or DELETE finds the same record.
CREATE TABLE scim_users (
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    user_id         text NOT NULL REFERENCES users ON DELETE CASCADE,
    external_id     text,
    user_name       text NOT NULL,
    active          boolean NOT NULL DEFAULT true,
    raw             jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id)
);
CREATE UNIQUE INDEX scim_users_username_idx ON scim_users (organization_id, lower(user_name));

CREATE TABLE scim_groups (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    display_name    text NOT NULL,
    external_id     text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX scim_groups_name_idx ON scim_groups (organization_id, lower(display_name));

CREATE TABLE scim_group_members (
    group_id        text NOT NULL REFERENCES scim_groups ON DELETE CASCADE,
    user_id         text NOT NULL REFERENCES users ON DELETE CASCADE,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX scim_group_members_user_idx ON scim_group_members (user_id);

-- ---------------------------------------------------------------------------
-- Service accounts
--
-- A non-human principal in one organisation. It takes the same role
-- bindings as a user and authenticates with client credentials or an API
-- key, so nothing downstream needs to know which it is.
CREATE TABLE service_accounts (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    client_id       text NOT NULL UNIQUE,
    secret_hash     bytea,
    secret_prefix   text NOT NULL DEFAULT '',
    server_id       text REFERENCES mcp_servers ON DELETE SET NULL,
    scopes          text[] NOT NULL DEFAULT '{}',
    last_used_at    timestamptz,
    disabled_at     timestamptz,
    created_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX service_accounts_org_idx ON service_accounts (organization_id);

-- ---------------------------------------------------------------------------
-- Password policy and history
--
-- One row per organisation; absent means the built-in default. History
-- stores hashes only, and is trimmed to the configured depth on write.
CREATE TABLE password_policies (
    organization_id  text PRIMARY KEY REFERENCES organizations ON DELETE CASCADE,
    min_length       int NOT NULL DEFAULT 12 CHECK (min_length BETWEEN 8 AND 256),
    require_classes  int NOT NULL DEFAULT 2 CHECK (require_classes BETWEEN 1 AND 4),
    history          int NOT NULL DEFAULT 5 CHECK (history BETWEEN 0 AND 24),
    max_age_days     int NOT NULL DEFAULT 0 CHECK (max_age_days BETWEEN 0 AND 3650),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE password_history (
    user_id    text NOT NULL REFERENCES users ON DELETE CASCADE,
    hash       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, hash)
);
CREATE INDEX password_history_user_idx ON password_history (user_id, created_at DESC);

ALTER TABLE users ADD COLUMN password_changed_at timestamptz;

-- ---------------------------------------------------------------------------
-- Row-level security

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'identity_providers', 'scim_users', 'scim_groups', 'scim_group_members', 'service_accounts'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY org_isolation ON %I USING (organization_id = current_org()) WITH CHECK (organization_id = current_org())', t);
    END LOOP;
END $$;

-- A password policy belongs to one organisation but is keyed by it.
ALTER TABLE password_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON password_policies
    USING (organization_id = current_org()) WITH CHECK (organization_id = current_org());

-- An identity link is reachable through the organisation that owns the
-- provider it came from.
ALTER TABLE user_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_identities FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON user_identities
    USING (EXISTS (SELECT 1 FROM identity_providers p WHERE p.id = user_identities.idp_id AND p.organization_id = current_org()))
    WITH CHECK (EXISTS (SELECT 1 FROM identity_providers p WHERE p.id = user_identities.idp_id AND p.organization_id = current_org()));

-- Sign-ins in flight and password history are never read through a tenant
-- connection; both are handled by the pre-authentication functions below.
ALTER TABLE sso_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE password_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_history FORCE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_providers, user_identities, scim_users, scim_groups,
    scim_group_members, service_accounts, password_policies TO supermcp_app;
GRANT SELECT ON sso_requests, password_history TO supermcp_app;

-- ---------------------------------------------------------------------------
-- Pre-authentication lookups. A sign-in through a provider has no tenant
-- yet: the callback arrives with a state parameter and nothing else.

CREATE OR REPLACE FUNCTION auth_idp(p_id text)
RETURNS TABLE (id text, organization_id text, name text, preset text, protocol text, issuer text, client_id text,
               client_secret_enc bytea, scopes text[], authorization_endpoint text, token_endpoint text,
               userinfo_endpoint text, jwks_uri text, discovered_at timestamptz, allowed_domains text[],
               jit_provisioning boolean, default_role_id text, groups_claim text, enabled boolean)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT p.id, p.organization_id, p.name, p.preset, p.protocol, p.issuer, p.client_id,
           p.client_secret_enc, p.scopes, p.authorization_endpoint, p.token_endpoint,
           p.userinfo_endpoint, p.jwks_uri, p.discovered_at, p.allowed_domains,
           p.jit_provisioning, p.default_role_id, p.groups_claim, p.enabled
    FROM identity_providers p WHERE p.id = p_id
$f$;

-- The sign-in page is anonymous and cannot know the tenant yet, so it
-- lists the enabled providers across the instance by name only.
CREATE OR REPLACE FUNCTION auth_idp_list()
RETURNS TABLE (id text, name text, preset text, organization_name text)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT p.id, p.name, p.preset, o.name
    FROM identity_providers p JOIN organizations o ON o.id = p.organization_id
    WHERE p.enabled ORDER BY o.name, p.name
$f$;

CREATE OR REPLACE FUNCTION auth_idp_discovery(p_id text, p_auth text, p_token text, p_userinfo text, p_jwks text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    UPDATE identity_providers SET authorization_endpoint = p_auth, token_endpoint = p_token,
        userinfo_endpoint = p_userinfo, jwks_uri = p_jwks, discovered_at = now(), updated_at = now()
    WHERE id = p_id
$f$;

CREATE OR REPLACE FUNCTION auth_sso_request_create(p_state text, p_idp text, p_nonce text, p_verifier text,
                                                   p_redirect text, p_expires timestamptz)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    INSERT INTO sso_requests (state, idp_id, nonce, code_verifier, redirect_after, expires_at)
    VALUES (p_state, p_idp, p_nonce, p_verifier, p_redirect, p_expires)
$f$;

-- Consumes the request and returns it: a state parameter is good once, so
-- the read and the write have to be the same statement.
CREATE OR REPLACE FUNCTION auth_sso_request_consume(p_state text)
RETURNS TABLE (state text, idp_id text, nonce text, code_verifier text, redirect_after text, expires_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    UPDATE sso_requests SET consumed_at = now()
    WHERE sso_requests.state = p_state AND consumed_at IS NULL
    RETURNING sso_requests.state, sso_requests.idp_id, sso_requests.nonce, sso_requests.code_verifier,
              sso_requests.redirect_after, sso_requests.expires_at
$f$;

CREATE OR REPLACE FUNCTION auth_identity(p_idp text, p_subject text)
RETURNS TABLE (user_id text, email text, disabled_at timestamptz)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT i.user_id, u.email, u.disabled_at
    FROM user_identities i JOIN users u ON u.id = i.user_id
    WHERE i.idp_id = p_idp AND i.subject = p_subject
$f$;

-- Links a provider subject to a user, creating the user and the membership
-- when just-in-time provisioning is on. Returns the user id.
CREATE OR REPLACE FUNCTION auth_sso_link(p_idp text, p_org text, p_subject text, p_email text, p_name text,
                                         p_new_user_id text, p_provision boolean)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
DECLARE v_user text;
BEGIN
    SELECT i.user_id INTO v_user FROM user_identities i WHERE i.idp_id = p_idp AND i.subject = p_subject;
    IF v_user IS NULL THEN
        -- An existing local account with the same address is adopted: the
        -- alternative is a second account the administrator cannot see.
        SELECT u.id INTO v_user FROM users u WHERE u.email_lower = lower(p_email);
    END IF;
    IF v_user IS NULL THEN
        IF NOT p_provision THEN
            RETURN NULL;
        END IF;
        INSERT INTO users (id, email, name) VALUES (p_new_user_id, p_email, p_name) RETURNING id INTO v_user;
    ELSE
        UPDATE users SET name = COALESCE(NULLIF(p_name, ''), name), updated_at = now() WHERE id = v_user;
    END IF;
    INSERT INTO user_identities (idp_id, subject, user_id, email, last_login_at)
    VALUES (p_idp, p_subject, v_user, p_email, now())
    ON CONFLICT (idp_id, subject) DO UPDATE SET email = EXCLUDED.email, last_login_at = now();
    INSERT INTO organization_members (user_id, organization_id) VALUES (v_user, p_org)
    ON CONFLICT (user_id, organization_id) DO UPDATE SET deactivated_at = NULL;
    RETURN v_user;
END
$f$;

-- Provisioning creates a person who is not yet a member of anything, which
-- no tenant-scoped policy can express. Returns the user id.
CREATE OR REPLACE FUNCTION auth_scim_upsert_user(p_org text, p_new_user_id text, p_email text, p_name text,
                                                 p_user_name text, p_external_id text, p_active boolean)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
DECLARE v_user text;
BEGIN
    SELECT u.id INTO v_user FROM users u WHERE u.email_lower = lower(p_email);
    IF v_user IS NULL THEN
        INSERT INTO users (id, email, name) VALUES (p_new_user_id, p_email, p_name) RETURNING id INTO v_user;
    ELSIF NULLIF(p_name, '') IS NOT NULL THEN
        UPDATE users SET name = p_name, updated_at = now() WHERE id = v_user;
    END IF;
    INSERT INTO organization_members (user_id, organization_id, deactivated_at)
    VALUES (v_user, p_org, CASE WHEN p_active THEN NULL ELSE now() END)
    ON CONFLICT (user_id, organization_id)
    DO UPDATE SET deactivated_at = CASE WHEN p_active THEN NULL ELSE now() END;
    INSERT INTO scim_users (organization_id, user_id, external_id, user_name, active)
    VALUES (p_org, v_user, NULLIF(p_external_id, ''), p_user_name, p_active)
    ON CONFLICT (organization_id, user_id)
    DO UPDATE SET external_id = EXCLUDED.external_id, user_name = EXCLUDED.user_name,
                  active = EXCLUDED.active, updated_at = now();
    RETURN v_user;
END
$f$;

CREATE OR REPLACE FUNCTION auth_service_account(p_client_id text)
RETURNS TABLE (id text, organization_id text, name text, secret_hash bytea, server_id text, scopes text[], disabled_at timestamptz)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT s.id, s.organization_id, s.name, s.secret_hash, s.server_id, s.scopes, s.disabled_at
    FROM service_accounts s WHERE s.client_id = p_client_id
$f$;

CREATE OR REPLACE FUNCTION auth_service_account_used(p_id text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    UPDATE service_accounts SET last_used_at = now() WHERE id = p_id
$f$;

-- Password changes: the policy and the recent hashes are read while the
-- caller is proving who they are, before a tenant is set.
CREATE OR REPLACE FUNCTION auth_user_by_id(p_id text)
RETURNS TABLE (id text, email text, name text, password_hash text, password_changed_at timestamptz, disabled_at timestamptz)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT u.id, u.email, u.name, u.password_hash, u.password_changed_at, u.disabled_at
    FROM users u WHERE u.id = p_id
$f$;

CREATE OR REPLACE FUNCTION auth_password_policy(p_org text)
RETURNS TABLE (min_length int, require_classes int, history int, max_age_days int)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT p.min_length, p.require_classes, p.history, p.max_age_days
    FROM password_policies p WHERE p.organization_id = p_org
$f$;

CREATE OR REPLACE FUNCTION auth_password_history(p_user text, p_limit int)
RETURNS TABLE (hash text)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT h.hash FROM password_history h WHERE h.user_id = p_user
    ORDER BY h.created_at DESC LIMIT p_limit
$f$;

CREATE OR REPLACE FUNCTION auth_password_set(p_user text, p_hash text, p_keep int)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
BEGIN
    UPDATE users SET password_hash = p_hash, password_changed_at = now(), updated_at = now() WHERE id = p_user;
    INSERT INTO password_history (user_id, hash) VALUES (p_user, p_hash) ON CONFLICT DO NOTHING;
    DELETE FROM password_history WHERE user_id = p_user AND hash NOT IN (
        SELECT h.hash FROM password_history h WHERE h.user_id = p_user ORDER BY h.created_at DESC LIMIT GREATEST(p_keep, 1)
    );
END
$f$;

-- Deactivating a principal has to reach every credential it holds, or the
-- account keeps working after the provisioning system says it should not.
-- Registration stores its password in the history too, so the very first
-- password counts against a reuse policy like every later one.
CREATE OR REPLACE FUNCTION auth_password_record(p_user text, p_hash text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    INSERT INTO password_history (user_id, hash) VALUES (p_user, p_hash) ON CONFLICT DO NOTHING
$f$;

CREATE OR REPLACE FUNCTION auth_session_verify(p_id text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    UPDATE sessions SET mfa_verified_at = now() WHERE id = p_id
$f$;

CREATE OR REPLACE FUNCTION auth_session_revoke_others(p_user text, p_keep text, p_reason text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason
    WHERE user_id = p_user AND id <> p_keep AND revoked_at IS NULL
$f$;

CREATE OR REPLACE FUNCTION auth_revoke_principal(p_org text, p_user text, p_reason text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
BEGIN
    UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason
    WHERE user_id = p_user AND revoked_at IS NULL;
    UPDATE api_keys SET revoked_at = now(), revoked_reason = p_reason
    WHERE organization_id = p_org AND principal_kind = 'user' AND principal_id = p_user AND revoked_at IS NULL;
    UPDATE oauth_refresh_tokens SET revoked_at = now()
    WHERE organization_id = p_org AND user_id = p_user AND revoked_at IS NULL;
END
$f$;

REVOKE ALL ON FUNCTION auth_idp(text), auth_password_record(text, text), auth_session_verify(text), auth_session_revoke_others(text, text, text), auth_scim_upsert_user(text, text, text, text, text, text, boolean), auth_user_by_id(text), auth_idp_list(), auth_idp_discovery(text, text, text, text, text),
    auth_sso_request_create(text, text, text, text, text, timestamptz), auth_sso_request_consume(text),
    auth_identity(text, text), auth_sso_link(text, text, text, text, text, text, boolean),
    auth_service_account(text), auth_service_account_used(text), auth_password_policy(text),
    auth_password_history(text, int), auth_password_set(text, text, int),
    auth_revoke_principal(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_idp(text), auth_password_record(text, text), auth_session_verify(text), auth_session_revoke_others(text, text, text), auth_scim_upsert_user(text, text, text, text, text, text, boolean), auth_user_by_id(text), auth_idp_list(), auth_idp_discovery(text, text, text, text, text),
    auth_sso_request_create(text, text, text, text, text, timestamptz), auth_sso_request_consume(text),
    auth_identity(text, text), auth_sso_link(text, text, text, text, text, text, boolean),
    auth_service_account(text), auth_service_account_used(text), auth_password_policy(text),
    auth_password_history(text, int), auth_password_set(text, text, int),
    auth_revoke_principal(text, text, text) TO supermcp_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS auth_idp(text), auth_password_record(text, text), auth_session_verify(text), auth_session_revoke_others(text, text, text), auth_scim_upsert_user(text, text, text, text, text, text, boolean), auth_user_by_id(text), auth_idp_list(), auth_idp_discovery(text, text, text, text, text),
    auth_sso_request_create(text, text, text, text, text, timestamptz), auth_sso_request_consume(text),
    auth_identity(text, text), auth_sso_link(text, text, text, text, text, text, boolean),
    auth_service_account(text), auth_service_account_used(text), auth_password_policy(text),
    auth_password_history(text, int), auth_password_set(text, text, int),
    auth_revoke_principal(text, text, text);
ALTER TABLE users DROP COLUMN IF EXISTS password_changed_at;
DROP TABLE IF EXISTS password_history, password_policies, service_accounts, scim_group_members,
    scim_groups, scim_users, user_identities, sso_requests, identity_providers;
-- +goose StatementEnd
