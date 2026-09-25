-- +goose Up

-- An MCP server either answers every request on its own (stateless, the
-- behaviour so far) or keeps a session per client in the memory of the
-- replica that initialised it (stateful), which is what lets the server
-- ask the client a question in the middle of a call.
--
-- Additive. A replica of the previous release neither reads nor writes
-- the column, and every existing row, like every row it inserts, reads as
-- stateless.
--
-- The constant default is a catalogue change and rewrites no row. The
-- check is verified against the existing rows while the ACCESS EXCLUSIVE
-- lock is held; mcp_servers holds one row per configured endpoint, so
-- that is a scan of a handful of rows. lock_timeout makes a migration
-- stuck behind a long transaction fail rather than queue every request to
-- the table behind it; run it again.
SET LOCAL lock_timeout = '5s';
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS sessions text NOT NULL DEFAULT 'stateless'
    CONSTRAINT mcp_servers_sessions_check CHECK (sessions IN ('stateless', 'stateful'));

-- +goose Down
ALTER TABLE mcp_servers DROP COLUMN IF EXISTS sessions;
