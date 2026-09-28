-- +goose NO TRANSACTION
-- +goose Up

-- The tool-call list (GET /api/v1/tool-calls) can be narrowed to one MCP
-- server, which had the slow path 00036 removed for a connector: with only
-- the (organization_id, created_at DESC) indexes, the filter reads the
-- workspace's calls newest first until the page is full, which for a quiet
-- server is every call the workspace ever made. On 300,000 calls in one
-- workspace, a server with a hundred of them read 30,800 pages (the whole
-- table, a parallel scan) with no window and 1,100 with a 24-hour one; with
-- this index, 5 and 4.
--
-- It adds one index to the table every tool call appends to. The key is
-- two ids and a timestamp, so the entry is small and fixed in size.
--
-- CONCURRENTLY so the build does not block those appends, hence NO
-- TRANSACTION above. A concurrent build that fails leaves an invalid index
-- under the same name and goose does not record the migration, so the DROP
-- first makes a rerun rebuild it rather than see the name and skip.
DROP INDEX CONCURRENTLY IF EXISTS tool_invocations_org_server_time_idx;
CREATE INDEX CONCURRENTLY IF NOT EXISTS tool_invocations_org_server_time_idx
    ON tool_invocations (organization_id, server_id, created_at DESC);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS tool_invocations_org_server_time_idx;
