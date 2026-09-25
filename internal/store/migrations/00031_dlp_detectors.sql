-- +goose NO TRANSACTION
-- +goose Up

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
-- reads and it cannot backtrack catastrophically. The application checks
-- it on every save: it compiles to at most 256 instructions, it is between
-- 3 and 512 bytes, it cannot match the empty string, it matches every
-- sample in must_match and none in must_not_match, and the detectors of
-- every policy naming it still fit that policy's cost budget. The checks
-- below are the part a database can hold on its own.
--
-- The samples are stored as written, here and nowhere else: the revision
-- history and the audit trail keep only how many there are. They are
-- examples an administrator types to prove the pattern does what it says,
-- and the screen asks for made-up values; nothing a tool call carried is
-- ever written here.
--
-- NO TRANSACTION so that the change to revisions below holds its exclusive
-- lock only for a catalogue update, and the check of the existing rows
-- runs under a lock that lets writes through. Every statement is safe to
-- run again if the migration is interrupted.
CREATE TABLE IF NOT EXISTS dlp_detectors (
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
    -- version), so an edit is a cache miss by construction. The trigger
    -- below bumps it for a change to the pattern that forgot to.
    version         bigint NOT NULL DEFAULT 1,
    created_by      text,
    updated_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);

ALTER TABLE dlp_detectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE dlp_detectors FORCE ROW LEVEL SECURITY;

-- +goose StatementBegin
DO $$
BEGIN
    CREATE POLICY org_isolation ON dlp_detectors
        USING (organization_id = current_org()) WITH CHECK (organization_id = current_org());
EXCEPTION WHEN duplicate_object THEN
    NULL;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT, UPDATE, DELETE ON dlp_detectors TO supermcp_app;

-- A replica caches a compiled pattern under its version. A change to the
-- pattern or the flags that left the version alone, such as an UPDATE an
-- operator runs by hand, would leave every replica running the old
-- program under the new row; this moves the version on for it. A write
-- that moved the version itself, as the application's do, is left alone.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION dlp_detectors_bump_version() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $f$
BEGIN
    IF (NEW.pattern IS DISTINCT FROM OLD.pattern OR NEW.flags IS DISTINCT FROM OLD.flags)
       AND NEW.version = OLD.version THEN
        NEW.version := OLD.version + 1;
    END IF;
    RETURN NEW;
END
$f$;
-- +goose StatementEnd

CREATE OR REPLACE TRIGGER dlp_detectors_bump_version
    BEFORE UPDATE ON dlp_detectors
    FOR EACH ROW EXECUTE FUNCTION dlp_detectors_bump_version();

-- The data-loss reader caches an organisation's detectors beside its
-- policies, so a change to either is the same news: 'dlp:<organization
-- id>' on the supermcp_cache channel, through the function 00020 added.
CREATE OR REPLACE TRIGGER supermcp_cache_notify
    AFTER INSERT OR UPDATE OR DELETE ON dlp_detectors
    FOR EACH ROW EXECUTE FUNCTION supermcp_cache_notify('dlp');

-- The history keeps detectors like it keeps policies. The constraint is
-- replaced under the same name, as 00028 did, but in two steps: one
-- statement swaps it NOT VALID, which is a catalogue change under a brief
-- exclusive lock, and the check of the existing rows follows under a lock
-- that lets inserts and updates of revisions through. The new list is a
-- superset, so a replica of the previous release is unaffected.
ALTER TABLE revisions
    DROP CONSTRAINT IF EXISTS revisions_entity_kind_check,
    ADD CONSTRAINT revisions_entity_kind_check
        CHECK (entity_kind IN ('connector', 'tool', 'server', 'role',
                               'dlp_policy', 'approval_policy', 'identity_provider', 'saml_provider',
                               'dlp_detector')) NOT VALID;
ALTER TABLE revisions VALIDATE CONSTRAINT revisions_entity_kind_check;

-- +goose Down
ALTER TABLE revisions DROP CONSTRAINT IF EXISTS revisions_entity_kind_check;
DELETE FROM revisions WHERE entity_kind = 'dlp_detector';
ALTER TABLE revisions ADD CONSTRAINT revisions_entity_kind_check
    CHECK (entity_kind IN ('connector', 'tool', 'server', 'role',
                           'dlp_policy', 'approval_policy', 'identity_provider', 'saml_provider'));
DROP TRIGGER IF EXISTS supermcp_cache_notify ON dlp_detectors;
DROP TRIGGER IF EXISTS dlp_detectors_bump_version ON dlp_detectors;
DROP FUNCTION IF EXISTS dlp_detectors_bump_version();
DROP TABLE IF EXISTS dlp_detectors;
