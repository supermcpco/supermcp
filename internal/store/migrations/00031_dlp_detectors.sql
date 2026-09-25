-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Custom data-loss detectors
--
-- The built-in detectors know card numbers, bank accounts and credentials.
-- They cannot know a company's own identifiers: a customer number, a
-- contract id, an internal ticket reference. A workspace writes those as
-- regular expressions here, and a policy picks one the way it picks a
-- built-in, by name: "custom:<name>" in dlp_policies.detectors.
--
-- The pattern is RE2 (Go's regexp), so its cost is linear in the text it
-- reads and it cannot backtrack catastrophically. It is validated by the
-- application on every save: it compiles, it is between 3 and 512 bytes,
-- it cannot match the empty string, and it matches every sample in
-- must_match and none in must_not_match. The checks below are the part a
-- database can hold on its own.
--
-- The samples are stored as written. They are examples an administrator
-- types to prove the pattern does what it says, and the screen asks for
-- made-up values; they are not findings and nothing a tool call carried
-- ever lands here.
CREATE TABLE dlp_detectors (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    -- Part of how a policy refers to the detector, so it never changes
    -- after the detector is created; see internal/dlp.
    name            text NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_-]{1,62}$'),
    description     text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
    pattern         text NOT NULL CHECK (octet_length(pattern) BETWEEN 3 AND 512),
    -- '' or 'i' (case-insensitive). A string rather than a boolean so a
    -- flag added later is a new value, not a new column.
    flags           text NOT NULL DEFAULT '' CHECK (flags IN ('', 'i')),
    must_match      text[] NOT NULL DEFAULT '{}',
    must_not_match  text[] NOT NULL DEFAULT '{}',
    enabled         boolean NOT NULL DEFAULT true,
    -- Bumped on every change. A PATCH names the version it read, and the
    -- compiled pattern is cached per replica under (organisation, id,
    -- version), so an edit is a cache miss by construction.
    version         bigint NOT NULL DEFAULT 1,
    created_by      text,
    updated_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);

ALTER TABLE dlp_detectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE dlp_detectors FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON dlp_detectors
    USING (organization_id = current_org()) WITH CHECK (organization_id = current_org());

GRANT SELECT, INSERT, UPDATE, DELETE ON dlp_detectors TO supermcp_app;

-- The data-loss reader caches an organisation's detectors beside its
-- policies, so a change to either is the same news: 'dlp:<organization
-- id>' on the supermcp_cache channel, through the function 00020 added.
CREATE OR REPLACE TRIGGER supermcp_cache_notify
    AFTER INSERT OR UPDATE OR DELETE ON dlp_detectors
    FOR EACH ROW EXECUTE FUNCTION supermcp_cache_notify('dlp');

-- The history keeps detectors like it keeps policies. The constraint is
-- dropped and re-added under the same name, as 00028 did; the new list is
-- a superset, so a replica of the previous release is unaffected.
ALTER TABLE revisions DROP CONSTRAINT IF EXISTS revisions_entity_kind_check;
ALTER TABLE revisions ADD CONSTRAINT revisions_entity_kind_check
    CHECK (entity_kind IN ('connector', 'tool', 'server', 'role',
                           'dlp_policy', 'approval_policy', 'identity_provider', 'saml_provider',
                           'dlp_detector'));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE revisions DROP CONSTRAINT IF EXISTS revisions_entity_kind_check;
DELETE FROM revisions WHERE entity_kind = 'dlp_detector';
ALTER TABLE revisions ADD CONSTRAINT revisions_entity_kind_check
    CHECK (entity_kind IN ('connector', 'tool', 'server', 'role',
                           'dlp_policy', 'approval_policy', 'identity_provider', 'saml_provider'));
DROP TRIGGER IF EXISTS supermcp_cache_notify ON dlp_detectors;
DROP TABLE IF EXISTS dlp_detectors;
-- +goose StatementEnd
