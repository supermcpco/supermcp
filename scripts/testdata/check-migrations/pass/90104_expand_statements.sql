-- +goose NO TRANSACTION
-- +goose Up
ALTER TABLE widgets ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'import'
    CHECK (source IN ('import', 'user'));
ALTER TABLE widgets ADD COLUMN edited_at timestamptz, ADD COLUMN n bigint GENERATED ALWAYS AS IDENTITY;
ALTER TABLE widgets ALTER COLUMN ts DROP DEFAULT, ALTER COLUMN owner DROP NOT NULL;
ALTER TABLE widgets DROP CONSTRAINT IF EXISTS widgets_kind_check;
ALTER TABLE widgets ADD CONSTRAINT widgets_kind_check CHECK (kind IN ('a', 'b'));
DROP INDEX CONCURRENTLY IF EXISTS "Widgets_Org_Seq_Idx";
CREATE INDEX CONCURRENTLY IF NOT EXISTS "Widgets_Org_Seq_Idx" ON widgets (org, seq);
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON widgets FROM supermcp_app;
CREATE TRIGGER widgets_notify AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON widgets
    FOR EACH STATEMENT EXECUTE FUNCTION notify();
DROP TRIGGER IF EXISTS widgets_notify ON widgets;
DROP FUNCTION IF EXISTS widgets_old(text);
