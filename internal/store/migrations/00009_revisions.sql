-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Revisions
--
-- One row per change to a connector, a tool or an MCP server, written in
-- the transaction that made the change. A revision that could be lost on
-- its own would be worse than none: it would leave a history that looks
-- complete while missing the change nobody can now account for.
--
-- snapshot and diff are `json`, not `jsonb`. jsonb normalises what it
-- stores — whitespace, key order, duplicate keys — and a snapshot that
-- comes back reordered is not the snapshot that was taken. The audit chain
-- learned this in 00006; there is no reason to learn it twice.
--
-- A rollback puts an earlier snapshot back through the service that owns
-- the entity, which records the result as an ordinary update. The history
-- of a mistake therefore survives its correction, and the numbering only
-- ever goes forwards.
CREATE TABLE revisions (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    entity_kind     text NOT NULL CHECK (entity_kind IN ('connector', 'tool', 'server')),
    entity_id       text NOT NULL,
    revision        int NOT NULL CHECK (revision > 0),
    snapshot        json NOT NULL,           -- the entity after the change, secrets digested
    diff            json,                    -- {"before":…,"after":…}, as the audit stream records it
    action          text NOT NULL CHECK (action IN ('create', 'update', 'delete')),
    actor_id        text,
    actor_display   text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- The number is allocated inside the writing transaction. Two writers
    -- that raced to the same one are stopped here rather than leaving a
    -- history with two fourth revisions; the index also serves the listing,
    -- which reads one entity newest first.
    UNIQUE (organization_id, entity_kind, entity_id, revision)
);

-- entity_id carries no foreign key on purpose: the three kinds live in
-- three tables, and the last revision of a deleted connector is the one
-- most worth keeping.

ALTER TABLE revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON revisions
    USING (organization_id = current_org()) WITH CHECK (organization_id = current_org());

-- History is appended, never edited: a rollback writes a new revision
-- rather than removing the one it disagrees with.
GRANT SELECT, INSERT ON revisions TO supermcp_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS revisions;
-- +goose StatementEnd
