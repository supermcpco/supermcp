-- +goose Up
-- +goose StatementBegin

-- Signing keys for MCP access tokens. Private material is sealed with the
-- instance data key; only the public JWK is readable.
CREATE TABLE signing_keys (
    kid          text PRIMARY KEY,
    alg          text NOT NULL,
    public_jwk   jsonb NOT NULL,
    private_enc  bytea NOT NULL,
    status       text NOT NULL CHECK (status IN ('next', 'active', 'retiring', 'retired')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    retire_at    timestamptz
);
CREATE INDEX signing_keys_status_idx ON signing_keys (status);

-- Clients registered through dynamic client registration or by an admin.
CREATE TABLE oauth_clients (
    id                         text PRIMARY KEY,
    client_id                  text NOT NULL UNIQUE,
    client_secret_hash         text,
    client_name                text NOT NULL DEFAULT '',
    redirect_uris              text[] NOT NULL DEFAULT '{}',
    grant_types                text[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
    response_types             text[] NOT NULL DEFAULT '{code}',
    token_endpoint_auth_method text NOT NULL DEFAULT 'none',
    scope                      text NOT NULL DEFAULT '',
    software_id                text,
    software_version           text,
    logo_uri                   text,
    client_uri                 text,
    status                     text NOT NULL DEFAULT 'approved' CHECK (status IN ('pending', 'approved', 'rejected')),
    registration_ip            inet,
    approved_by                text,
    approved_at                timestamptz,
    last_used_at               timestamptz,
    created_at                 timestamptz NOT NULL DEFAULT now()
);

-- Authorization codes are single use and short lived.
CREATE TABLE oauth_codes (
    code                  text PRIMARY KEY,
    client_id             text NOT NULL,
    user_id               text NOT NULL REFERENCES users ON DELETE CASCADE,
    organization_id       text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    server_id             text,
    redirect_uri          text NOT NULL,
    code_challenge        text NOT NULL,
    code_challenge_method text NOT NULL,
    scope                 text NOT NULL DEFAULT '',
    resource              text,
    expires_at            timestamptz NOT NULL,
    consumed_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX oauth_codes_expiry_idx ON oauth_codes (expires_at);

-- Refresh tokens rotate. Reuse of a consumed token revokes the family,
-- which is the only reliable signal that a token was stolen.
CREATE TABLE oauth_refresh_tokens (
    id              text PRIMARY KEY,
    token_hash      bytea NOT NULL UNIQUE,
    family_id       text NOT NULL,
    parent_id       text,
    client_id       text NOT NULL,
    user_id         text NOT NULL REFERENCES users ON DELETE CASCADE,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    server_id       text,
    scope           text NOT NULL DEFAULT '',
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX oauth_refresh_family_idx ON oauth_refresh_tokens (family_id);
CREATE INDEX oauth_refresh_expiry_idx ON oauth_refresh_tokens (expires_at);

-- Pending authorization requests, keyed by a browser-visible state.
CREATE TABLE oauth_sessions (
    id                    text PRIMARY KEY,
    client_id             text NOT NULL,
    redirect_uri          text NOT NULL,
    state                 text,
    code_challenge        text NOT NULL,
    code_challenge_method text NOT NULL,
    scope                 text NOT NULL DEFAULT '',
    resource              text,
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX oauth_sessions_expiry_idx ON oauth_sessions (expires_at);

-- Clients, sessions and signing keys are instance-level: a client is not
-- owned by a tenant, and an authorization request has no tenant until the
-- user consents. Codes and refresh tokens do carry a tenant, so they get
-- the same isolation as every other tenant table. The authorization server
-- reaches them through the maintenance role (tenant.Bypass), because the
-- token endpoint runs before any tenant context exists.
ALTER TABLE oauth_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON oauth_codes USING (organization_id = current_org()) WITH CHECK (organization_id = current_org());

ALTER TABLE oauth_refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_refresh_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON oauth_refresh_tokens USING (organization_id = current_org()) WITH CHECK (organization_id = current_org());

GRANT SELECT, INSERT, UPDATE, DELETE ON signing_keys, oauth_clients, oauth_codes, oauth_refresh_tokens, oauth_sessions TO supermcp_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS oauth_sessions, oauth_refresh_tokens, oauth_codes, oauth_clients, signing_keys;
-- +goose StatementEnd
