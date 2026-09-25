-- +goose NO TRANSACTION
-- +goose Up

-- The export sweep (internal/audit/exporter.go) and the export-lag query
-- (internal/audit/exportlag.go) both read one organisation's events after
-- a cursor: organization_id = $1 AND seq > $2 ORDER BY seq. No index
-- covered that, so Postgres chose between the org+time index, which does
-- not order by seq, and the primary key on seq, which walks every
-- organisation's events after the cursor. Either grows with the table.
--
-- CONCURRENTLY so the build does not block writes to audit_events, which
-- every request appends to. That cannot run inside a transaction, hence
-- NO TRANSACTION above. Migrate still holds its advisory lock on a
-- separate session that is not in a transaction, so the build does not
-- wait on it.
--
-- A concurrent build that fails (cancelled, timed out, a lost
-- connection) leaves an invalid index behind under the same name, and
-- goose does not record the migration as applied. The DROP first makes a
-- rerun rebuild it instead of seeing the name and skipping, which is what
-- IF NOT EXISTS alone would do. On a clean database it drops nothing.
DROP INDEX CONCURRENTLY IF EXISTS audit_events_org_seq_idx;
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_org_seq_idx
    ON audit_events (organization_id, seq);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS audit_events_org_seq_idx;
