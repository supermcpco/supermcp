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

-- On a stateful session the server can ask the person behind the client
-- to confirm a call it has held for approval. Their confirmation, and the
-- note they add for the approver, are recorded on the request. It is not
-- an approval: the request stays pending until someone else decides it.
--
-- Two columns with constant defaults (none, and the empty string), a
-- catalogue change that rewrites no row. 00012 grants the application
-- UPDATE on named columns of approval_requests only, so these two are
-- added to that grant; nothing else about the request becomes writable.
ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS acknowledged_at timestamptz;
ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS acknowledgement text NOT NULL DEFAULT '';
GRANT UPDATE (acknowledged_at, acknowledgement) ON approval_requests TO supermcp_app;

-- +goose Down
REVOKE UPDATE (acknowledged_at, acknowledgement) ON approval_requests FROM supermcp_app;
ALTER TABLE approval_requests DROP COLUMN IF EXISTS acknowledgement;
ALTER TABLE approval_requests DROP COLUMN IF EXISTS acknowledged_at;
ALTER TABLE mcp_servers DROP COLUMN IF EXISTS sessions;
