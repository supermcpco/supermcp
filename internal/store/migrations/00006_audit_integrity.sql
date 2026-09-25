-- supermcp:breaking (deletes every audit event and anchor and retypes three columns;
-- docs/UPGRADING.md, "migration 00006" under 1.0.0)
-- +goose Up
-- +goose StatementBegin

-- The chain hashed the JSON columns as the writer had serialised them, and
-- then re-read them to verify. Postgres does not hand jsonb back the way it
-- was given: it normalises whitespace, orders keys by length and drops
-- duplicates. Every event carrying a diff, a payload or metadata therefore
-- failed verification the moment it was read, which is the one thing this
-- table exists to make impossible.
--
-- Two changes fix it and one more earns its place while we are here:
--
--   * The JSON columns become `json`, which Postgres stores as the text it
--     was given, so re-reading returns the bytes that were hashed.
--   * content_hash records the digest of that content at write time. The
--     chain is built over the digest rather than over the content, so the
--     content can later be removed without breaking the chain.
--   * scrubbed_at marks a row whose content was removed under a retention
--     rule or a legal obligation. Verification then checks the chain but
--     not the content, and says which rows it could not check.
--
-- Rows written before this migration cannot be verified: their digests do
-- not exist and their content has already been normalised. There is no
-- supported release with such rows, so they are removed rather than
-- carried forward as permanently broken links.

DELETE FROM audit_anchors;
DELETE FROM audit_events;

ALTER TABLE audit_events
    ALTER COLUMN diff    TYPE json USING diff::text::json,
    ALTER COLUMN payload TYPE json USING payload::text::json,
    ALTER COLUMN meta    TYPE json USING meta::text::json,
    ADD COLUMN content_hash bytea NOT NULL DEFAULT '\x00',
    ADD COLUMN scrubbed_at  timestamptz;

ALTER TABLE audit_events ALTER COLUMN content_hash DROP DEFAULT;

-- Scrubbing removes content from a row that stays in the chain. It is the
-- only edit the app role may make, and it may not touch anything else.
GRANT UPDATE (diff, payload, scrubbed_at) ON audit_events TO supermcp_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
REVOKE UPDATE ON audit_events FROM supermcp_app;
ALTER TABLE audit_events
    DROP COLUMN IF EXISTS content_hash,
    DROP COLUMN IF EXISTS scrubbed_at,
    ALTER COLUMN diff    TYPE jsonb USING diff::text::jsonb,
    ALTER COLUMN payload TYPE jsonb USING payload::text::jsonb,
    ALTER COLUMN meta    TYPE jsonb USING meta::text::jsonb;
-- +goose StatementEnd
