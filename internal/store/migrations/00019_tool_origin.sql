-- +goose Up
-- +goose StatementBegin

-- A tool can now be edited by hand, and one that someone has edited must
-- survive the next catalog re-sync rather than be overwritten by it. That
-- needs two facts the table did not keep: where the tool came from, and
-- whether a person has changed it since.
--
-- source is 'catalog' for a tool installed from the adapter catalog,
-- 'import' for one that came with an imported spec or a hand-made
-- connector, and 'custom' for one created in the tool editor. Only custom
-- tools may be deleted; the others can only be disabled, because a re-sync
-- or re-import would bring them back.
--
-- The default is 'import' so that an older replica still running during a
-- rolling upgrade, which does not know the column, writes a valid row; it
-- labels a catalog install as an import until the next re-sync.
ALTER TABLE tools ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'import'
    CONSTRAINT tools_source_check CHECK (source IN ('catalog', 'import', 'custom'));
ALTER TABLE tools ADD COLUMN IF NOT EXISTS edited_at timestamptz;
ALTER TABLE tools ADD COLUMN IF NOT EXISTS edited_by text;

-- Every tool of a connector installed from the catalog came from the
-- catalog. This runs as the maintenance role, which is not subject to
-- row-level security, so it reaches every organisation's rows.
UPDATE tools t SET source = 'catalog'
  FROM connectors c
 WHERE c.id = t.connector_id AND c.catalog_slug IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tools DROP COLUMN IF EXISTS edited_by;
ALTER TABLE tools DROP COLUMN IF EXISTS edited_at;
ALTER TABLE tools DROP COLUMN IF EXISTS source;
-- +goose StatementEnd
