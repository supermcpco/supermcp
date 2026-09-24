-- +goose Up
-- +goose StatementBegin

-- Binary tool results too large to put in a transcript are handed back
-- as a link to /api/v1/blobs/{id}. They were held in the memory of the
-- replica that produced them, so with more than one replica the link
-- answered 404 whenever the fetch landed on another one. This table is
-- where they live when there is no Redis to share them through, and the
-- fallback when there is and it fails.
--
-- A blob answers only to the principal it was stored for, so the owner
-- is part of every read, and it lives minutes: a sweep deletes what has
-- expired.
CREATE TABLE tool_blobs (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    principal_id    text NOT NULL,
    media_type      text NOT NULL,
    name            text NOT NULL DEFAULT '',
    data            bytea NOT NULL,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tool_blobs_expiry_idx ON tool_blobs (expires_at);

ALTER TABLE tool_blobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_blobs FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON tool_blobs
    USING (organization_id = current_org()) WITH CHECK (organization_id = current_org());

-- Written once and read back; the sweep runs as the maintenance role.
REVOKE ALL ON tool_blobs FROM supermcp_app;
GRANT SELECT, INSERT ON tool_blobs TO supermcp_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS tool_blobs;
-- +goose StatementEnd
