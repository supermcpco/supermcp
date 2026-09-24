-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- SAML 2.0 single sign-on
--
-- SAML is not OpenID Connect with different spelling, so it gets tables of
-- its own rather than more columns on identity_providers. The differences
-- that matter here: we are a service provider with our own signing key
-- pair per organisation, the identity provider is described by a metadata
-- document rather than a discovery document, and an assertion is a signed
-- bearer token that must be accepted exactly once.

-- saml_providers is one identity provider per organisation.
--
-- The two halves are kept apart on purpose. entity_id, signing_cert and
-- signing_key_enc describe us, and are what an administrator registers
-- with their identity provider; idp_* describe them, and are refreshed
-- from their metadata. Rotating one half does not disturb the other.
--
-- signing_key_enc holds the private half sealed with the organisation's
-- data key, like every other secret here. The certificate beside it is
-- public by definition: it is in the metadata document we publish.
CREATE TABLE saml_providers (
    id                  text PRIMARY KEY,
    organization_id     text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    name                text NOT NULL,

    -- Our side of the federation.
    entity_id           text NOT NULL,
    signing_cert        bytea NOT NULL,   -- DER, self-signed, published in our metadata
    signing_key_enc     bytea NOT NULL,   -- PKCS#8 DER, sealed

    -- Their side, as read from the metadata document.
    idp_entity_id       text NOT NULL,
    idp_sso_url         text NOT NULL,
    -- base64 DER, in the order the metadata listed them, so an identity
    -- provider part-way through a certificate rollover still verifies.
    idp_certificates    text[] NOT NULL DEFAULT '{}',
    -- Set when the metadata came from a URL, so it can be refreshed.
    metadata_url        text NOT NULL DEFAULT '',
    metadata_fetched_at timestamptz,

    -- What the assertion has to say about the person, and what we do with
    -- it. Empty means "try the usual names for this attribute".
    email_attribute     text NOT NULL DEFAULT '',
    name_attribute      text NOT NULL DEFAULT '',
    groups_attribute    text NOT NULL DEFAULT '',
    allowed_domains     text[] NOT NULL DEFAULT '{}',
    jit_provisioning    boolean NOT NULL DEFAULT true,
    default_role_id     text REFERENCES roles ON DELETE SET NULL,
    enabled             boolean NOT NULL DEFAULT true,

    created_by          text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT saml_provider_entity_named CHECK (entity_id <> ''),
    CONSTRAINT saml_provider_idp_named CHECK (idp_entity_id <> '' AND idp_sso_url <> '')
);
CREATE INDEX saml_providers_org_idx ON saml_providers (organization_id);
-- Our entity id is the audience an assertion is restricted to, so two
-- providers may not share one.
CREATE UNIQUE INDEX saml_providers_entity_idx ON saml_providers (entity_id);

-- A sign-in in flight. The row holds where to send the browser afterwards
-- and proves we started this exchange; the assertion's InResponseTo names
-- it. Unlike an OAuth state parameter it is deliberately not single-use:
-- in SAML the thing that may be used only once is the assertion, and that
-- is what saml_assertions enforces. Making this row one-shot as well would
-- only move a replay's refusal to a less accurate message.
CREATE TABLE saml_requests (
    id             text PRIMARY KEY,
    provider_id    text NOT NULL REFERENCES saml_providers ON DELETE CASCADE,
    redirect_after text NOT NULL DEFAULT '',
    -- The digest of a cookie set in the browser that started this
    -- sign-in. An assertion is a bearer document: without this, somebody
    -- can start a sign-in of their own and post the answer into another
    -- person's browser, and that person is then signed in as them. The
    -- digest rather than the value, so the table cannot be used to forge
    -- the cookie.
    binding        text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL
);
CREATE INDEX saml_requests_expiry_idx ON saml_requests (expires_at);

-- An assertion id that has been spent. An assertion is a bearer token
-- that anyone who can read it can present, so it is accepted once and
-- refused for ever after. Rows are kept until the assertion they name
-- could no longer be valid anyway, then swept: beyond that point the
-- expiry check refuses the replay on its own.
CREATE TABLE saml_assertions (
    provider_id     text NOT NULL REFERENCES saml_providers ON DELETE CASCADE,
    assertion_id    text NOT NULL,
    not_on_or_after timestamptz NOT NULL,
    used_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, assertion_id)
);
CREATE INDEX saml_assertions_expiry_idx ON saml_assertions (not_on_or_after);

-- The link between an identity provider's subject and our user. The
-- subject, not the email address, is the identity: an address can be
-- reassigned to a different person.
CREATE TABLE saml_identities (
    provider_id   text NOT NULL REFERENCES saml_providers ON DELETE CASCADE,
    subject       text NOT NULL,
    user_id       text NOT NULL REFERENCES users ON DELETE CASCADE,
    email         text NOT NULL DEFAULT '',
    last_login_at timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, subject)
);
CREATE INDEX saml_identities_user_idx ON saml_identities (user_id);

-- ---------------------------------------------------------------------------
-- Row-level security

ALTER TABLE saml_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_providers FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON saml_providers
    USING (organization_id = current_org()) WITH CHECK (organization_id = current_org());

-- An identity link is reachable through the organisation that owns the
-- provider it came from, exactly as user_identities is.
ALTER TABLE saml_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_identities FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON saml_identities
    USING (EXISTS (SELECT 1 FROM saml_providers p
                   WHERE p.id = saml_identities.provider_id AND p.organization_id = current_org()))
    WITH CHECK (EXISTS (SELECT 1 FROM saml_providers p
                        WHERE p.id = saml_identities.provider_id AND p.organization_id = current_org()));

-- A sign-in in flight and a spent assertion are never read through a
-- tenant connection: the assertion arrives from the identity provider
-- with no session behind it. Security enabled with no policy, as
-- sso_requests has, so only the pre-authentication functions below reach
-- them.
ALTER TABLE saml_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE saml_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_assertions FORCE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON saml_providers, saml_identities TO supermcp_app;
-- 00002 grants the application everything on every new table by default.
-- Take that back here: replay protection is only worth having if the
-- process that consumes an assertion cannot also delete the record that
-- says it was already consumed.
REVOKE ALL ON saml_requests, saml_assertions FROM supermcp_app;
GRANT SELECT ON saml_requests, saml_assertions TO supermcp_app;

-- ---------------------------------------------------------------------------
-- Pre-authentication lookups. An assertion arrives at the consumer
-- endpoint with no tenant and no session: the URL names the provider and
-- the signature is the only thing vouching for the rest.

CREATE OR REPLACE FUNCTION auth_saml_provider(p_id text)
RETURNS TABLE (id text, organization_id text, name text, entity_id text, signing_cert bytea,
               signing_key_enc bytea, idp_entity_id text, idp_sso_url text, idp_certificates text[],
               metadata_url text, metadata_fetched_at timestamptz, email_attribute text,
               name_attribute text, groups_attribute text, allowed_domains text[],
               jit_provisioning boolean, default_role_id text, enabled boolean)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT p.id, p.organization_id, p.name, p.entity_id, p.signing_cert, p.signing_key_enc,
           p.idp_entity_id, p.idp_sso_url, p.idp_certificates, p.metadata_url, p.metadata_fetched_at,
           p.email_attribute, p.name_attribute, p.groups_attribute, p.allowed_domains,
           p.jit_provisioning, p.default_role_id, p.enabled
    FROM saml_providers p WHERE p.id = p_id
$f$;

-- The sign-in page is anonymous and cannot know the tenant yet, so it
-- lists the enabled providers across the instance by name only.
CREATE OR REPLACE FUNCTION auth_saml_provider_list()
RETURNS TABLE (id text, name text, organization_name text)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT p.id, p.name, o.name
    FROM saml_providers p JOIN organizations o ON o.id = p.organization_id
    WHERE p.enabled ORDER BY o.name, p.name
$f$;

CREATE OR REPLACE FUNCTION auth_saml_request_create(p_id text, p_provider text, p_redirect text,
                                                    p_expires timestamptz, p_binding text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    INSERT INTO saml_requests (id, provider_id, redirect_after, expires_at, binding)
    VALUES (p_id, p_provider, p_redirect, p_expires, p_binding)
$f$;

CREATE OR REPLACE FUNCTION auth_saml_request(p_id text, p_provider text)
RETURNS TABLE (id text, redirect_after text, expires_at timestamptz, binding text)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT r.id, r.redirect_after, r.expires_at, r.binding
    FROM saml_requests r WHERE r.id = p_id AND r.provider_id = p_provider
$f$;

-- Spends an assertion id. Returns true the first time and false every
-- time after, so the caller learns "already used" without a second query
-- that another request could slip between.
CREATE OR REPLACE FUNCTION auth_saml_assertion_use(p_provider text, p_assertion text,
                                                   p_not_on_or_after timestamptz)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
BEGIN
    INSERT INTO saml_assertions (provider_id, assertion_id, not_on_or_after)
    VALUES (p_provider, p_assertion, p_not_on_or_after)
    ON CONFLICT (provider_id, assertion_id) DO NOTHING;
    RETURN FOUND;
END
$f$;

-- Links an assertion subject to a user, creating the user and the
-- membership when just-in-time provisioning is on. Returns the user id,
-- or null when there is no account and provisioning is off. The body
-- mirrors auth_sso_link: the same adoption rule, so someone who already
-- has a local account does not acquire a second one.
CREATE OR REPLACE FUNCTION auth_saml_link(p_provider text, p_org text, p_subject text, p_email text,
                                          p_name text, p_new_user_id text, p_provision boolean)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
DECLARE v_user text;
BEGIN
    SELECT i.user_id INTO v_user FROM saml_identities i
    WHERE i.provider_id = p_provider AND i.subject = p_subject;
    IF v_user IS NULL THEN
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
    INSERT INTO saml_identities (provider_id, subject, user_id, email, last_login_at)
    VALUES (p_provider, p_subject, v_user, p_email, now())
    ON CONFLICT (provider_id, subject) DO UPDATE SET email = EXCLUDED.email, last_login_at = now();
    INSERT INTO organization_members (user_id, organization_id) VALUES (v_user, p_org)
    ON CONFLICT (user_id, organization_id) DO UPDATE SET deactivated_at = NULL;
    RETURN v_user;
END
$f$;

REVOKE ALL ON FUNCTION auth_saml_provider(text), auth_saml_provider_list(),
    auth_saml_request_create(text, text, text, timestamptz, text), auth_saml_request(text, text),
    auth_saml_assertion_use(text, text, timestamptz),
    auth_saml_link(text, text, text, text, text, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_saml_provider(text), auth_saml_provider_list(),
    auth_saml_request_create(text, text, text, timestamptz, text), auth_saml_request(text, text),
    auth_saml_assertion_use(text, text, timestamptz),
    auth_saml_link(text, text, text, text, text, text, boolean) TO supermcp_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS auth_saml_provider(text), auth_saml_provider_list(),
    auth_saml_request_create(text, text, text, timestamptz, text), auth_saml_request(text, text),
    auth_saml_assertion_use(text, text, timestamptz),
    auth_saml_link(text, text, text, text, text, text, boolean);
DROP TABLE IF EXISTS saml_identities, saml_assertions, saml_requests, saml_providers;
-- +goose StatementEnd
