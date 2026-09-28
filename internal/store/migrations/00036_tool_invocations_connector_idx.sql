-- +goose NO TRANSACTION
-- +goose Up

-- The tool-call list (GET /api/v1/tool-calls) can be narrowed to one
-- connector. With only the (organization_id, created_at DESC) index, that
-- filter walks the workspace's calls newest first and fetches each one from
-- the heap to read its connector, until the page is full: fine for a busy
-- connector, and every call the workspace ever made for a quiet one. On
-- 300,000 calls, a connector with a hundred of them took 2.5 s with no
-- window and 0.6 s (a parallel scan of the table) with a 24-hour one; with
-- this index both are under 2 ms.
--
-- It adds one index to the table every tool call appends to. The key is
-- two ids and a timestamp, so the entry is small and fixed in size.
--
-- CONCURRENTLY so the build does not block those appends, hence NO
-- TRANSACTION above. A concurrent build that fails leaves an invalid index
-- under the same name and goose does not record the migration, so the DROP
-- first makes a rerun rebuild it rather than see the name and skip.
DROP INDEX CONCURRENTLY IF EXISTS tool_invocations_org_connector_time_idx;
CREATE INDEX CONCURRENTLY IF NOT EXISTS tool_invocations_org_connector_time_idx
    ON tool_invocations (organization_id, connector_id, created_at DESC);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS tool_invocations_org_connector_time_idx;
