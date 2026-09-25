-- +goose NO TRANSACTION
-- +goose Up

-- An OpenID Connect provider says which of its answers count as a second
-- factor: mfa_amr lists amr values (RFC 8176), any of which in a verified
-- ID token counts, and mfa_acr lists acr values that count. NULL or empty
-- in both is no rule, and a sign-in through such a provider is not
-- recorded as having a second factor. Providers configured before this
-- migration have no rule until an administrator gives them one.
--
-- A session keeps the methods the provider reported (auth_methods, the
-- ID token's amr for OpenID Connect, what the AuthnContext class names for
-- SAML), so a token can say how its holder signed in. The column is NULL
-- for a password session and for a single sign-on session opened by a
-- release that did not judge the provider's answer: every such OpenID
-- Connect session was marked verified whatever the provider did. The
-- session is read through auth_session_get, which reports no second
-- factor for an sso session whose auth_methods is NULL. A session this
-- release opens through a provider always has auth_methods, '{}' when the
-- provider named nothing.
--
-- Expand only. A replica of the previous release still running during the
-- roll reads providers through auth_idp, opens sessions through the
-- ten-argument auth_session_open and reads them through
-- auth_session_load, all left as they were. The sso sessions it opens have
-- no auth_methods, so this release does not count them as verified.
--
-- NO TRANSACTION so that no statement here holds a lock for long: every
-- request reads the sessions table. The columns have no default, which
-- is a catalogue change only, and each statement is safe to run again.
ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS mfa_amr text[];
ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS mfa_acr text[];
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS auth_methods text[];

-- +goose StatementBegin
-- auth_idp with the second-factor rule, for the callback, which runs
-- before anyone knows which organisation the request is for.
CREATE OR REPLACE FUNCTION auth_idp_load(p_id text)
RETURNS TABLE (id text, organization_id text, name text, preset text, protocol text, issuer text, client_id text,
               client_secret_enc bytea, scopes text[], authorization_endpoint text, token_endpoint text,
               userinfo_endpoint text, jwks_uri text, discovered_at timestamptz, allowed_domains text[],
               jit_provisioning boolean, default_role_id text, groups_claim text, enabled boolean,
               mfa_amr text[], mfa_acr text[])
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT p.id, p.organization_id, p.name, p.preset, p.protocol, p.issuer, p.client_id,
           p.client_secret_enc, p.scopes, p.authorization_endpoint, p.token_endpoint,
           p.userinfo_endpoint, p.jwks_uri, p.discovered_at, p.allowed_domains,
           p.jit_provisioning, p.default_role_id, p.groups_claim, p.enabled,
           COALESCE(p.mfa_amr, '{}'), COALESCE(p.mfa_acr, '{}')
    FROM identity_providers p WHERE p.id = p_id
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
-- auth_session_open with the methods the provider reported. A provider
-- session always records them, '{}' when there were none, which is what
-- tells auth_session_get it was judged by this release.
CREATE OR REPLACE FUNCTION auth_session_open(p_id text, p_user_id text, p_org text, p_idle timestamptz, p_abs timestamptz,
                                             p_method text, p_provider text, p_at timestamptz, p_ip inet, p_ua text,
                                             p_methods text[])
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    INSERT INTO sessions (id, user_id, organization_id, idle_expires_at, absolute_expires_at, auth_method,
                          auth_provider_id, authenticated_at, ip, user_agent, auth_methods)
    VALUES (p_id, p_user_id, p_org, p_idle, p_abs, p_method, p_provider,
            COALESCE(p_at, '-infinity'::timestamptz), p_ip, p_ua,
            CASE WHEN p_method IN ('sso', 'saml') THEN COALESCE(p_methods, '{}') ELSE p_methods END)
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
-- auth_session_load with the reported methods. An OpenID Connect session
-- without them was opened by a release that marked every such session
-- verified, so its mfa_verified_at says nothing and reads as NULL.
CREATE OR REPLACE FUNCTION auth_session_get(p_id text)
RETURNS TABLE (id text, user_id text, organization_id text, idle_expires_at timestamptz, absolute_expires_at timestamptz,
               mfa_verified_at timestamptz, auth_method text, revoked_at timestamptz, last_seen_at timestamptz,
               authenticated_at timestamptz, auth_provider_id text, auth_methods text[])
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT s.id, s.user_id, s.organization_id, s.idle_expires_at, s.absolute_expires_at,
           CASE WHEN s.auth_method = 'sso' AND s.auth_methods IS NULL THEN NULL ELSE s.mfa_verified_at END,
           s.auth_method, s.revoked_at, s.last_seen_at,
           NULLIF(s.authenticated_at, '-infinity'::timestamptz), s.auth_provider_id, s.auth_methods
    FROM sessions s WHERE s.id = p_id
$f$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION auth_idp_load(text),
    auth_session_open(text, text, text, timestamptz, timestamptz, text, text, timestamptz, inet, text, text[]),
    auth_session_get(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_idp_load(text),
    auth_session_open(text, text, text, timestamptz, timestamptz, text, text, timestamptz, inet, text, text[]),
    auth_session_get(text) TO supermcp_app;

-- +goose Down
DROP FUNCTION IF EXISTS auth_session_get(text),
    auth_session_open(text, text, text, timestamptz, timestamptz, text, text, timestamptz, inet, text, text[]),
    auth_idp_load(text);
ALTER TABLE sessions DROP COLUMN IF EXISTS auth_methods;
ALTER TABLE identity_providers DROP COLUMN IF EXISTS mfa_acr;
ALTER TABLE identity_providers DROP COLUMN IF EXISTS mfa_amr;
