-- +goose NO TRANSACTION
-- +goose Up

-- The usage analytics (internal/httpapi/analytics.go) aggregate one
-- organisation's calls over a window of up to 90 days: organization_id =
-- $1 AND created_at in [$2, $3), reading status, duration_ms, upstream_ms
-- and the tool, connector and server columns. The (organization_id,
-- created_at DESC) index found the rows but every one of them still had to
-- be fetched from the heap, where calls from every organisation sit
-- interleaved in arrival order next to their arguments and results. On 4
-- million calls that meant one heap page per call for a small workspace
-- and a parallel scan of the whole table for a large one (14 s).
--
-- This index has the same key, so the tool-call list reads it exactly as
-- it read the old one, and carries the columns the aggregates need, so they
-- become an index-only scan (the same large workspace: 0.35 s). It
-- replaces the old index rather than joining it, which keeps the number of
-- indexes every tool call writes to where it was.
--
-- CONCURRENTLY so neither build nor drop blocks writes to tool_invocations,
-- which every tool call appends to. That cannot run inside a transaction,
-- hence NO TRANSACTION above.
--
-- A concurrent build that fails leaves an invalid index behind under the
-- same name, and goose does not record the migration as applied. The DROP
-- first makes a rerun rebuild it instead of seeing the name and skipping.
-- The old index is dropped only after the new one is built, so a rerun
-- from any point still has one of the two.
DROP INDEX CONCURRENTLY IF EXISTS tool_invocations_org_time_cover_idx;
CREATE INDEX CONCURRENTLY IF NOT EXISTS tool_invocations_org_time_cover_idx
    ON tool_invocations (organization_id, created_at DESC)
    INCLUDE (status, duration_ms, upstream_ms, tool_id, tool_name, connector_id, server_id);
DROP INDEX CONCURRENTLY IF EXISTS tool_invocations_org_time_idx;

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS tool_invocations_org_time_idx;
CREATE INDEX CONCURRENTLY IF NOT EXISTS tool_invocations_org_time_idx
    ON tool_invocations (organization_id, created_at DESC);
DROP INDEX CONCURRENTLY IF EXISTS tool_invocations_org_time_cover_idx;
