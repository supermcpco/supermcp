-- +goose Up
-- +goose StatementBegin

-- One append-only stream for everything that matters: sign-ins, admin
-- changes, tool calls, denied access, key rotation. Each row carries the
-- hash of the previous one, so a deletion or an edit breaks the chain and
-- `supermcp audit verify` says where.
CREATE TABLE audit_events (
    seq             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id              uuid NOT NULL UNIQUE,
    ts              timestamptz NOT NULL DEFAULT now(),
    organization_id text,                    -- NULL for instance-level events
    category        text NOT NULL,           -- auth | admin | tool | authz | secrets | system
    action          text NOT NULL,           -- connector.update, tool.invoke, session.create, ...
    outcome         text NOT NULL CHECK (outcome IN ('success', 'failure', 'denied', 'pending')),
    actor_kind      text NOT NULL,
    actor_id        text,
    actor_display   text NOT NULL DEFAULT '',
    on_behalf_of    text,                    -- OAuth client acting for a user
    target_kind     text,
    target_id       text,
    target_display  text NOT NULL DEFAULT '',
    request_id      text,
    session_id      text,
    ip              inet,
    user_agent      text,
    diff            jsonb,                   -- {"before":…,"after":…} with secrets redacted
    payload         jsonb,                   -- tool input/output, subject to the org's policy
    meta            jsonb,
    prev_hash       bytea NOT NULL,
    hash            bytea NOT NULL,
    legal_hold      boolean NOT NULL DEFAULT false
);
CREATE INDEX audit_events_org_time_idx ON audit_events (organization_id, ts DESC);
CREATE INDEX audit_events_action_idx ON audit_events (organization_id, category, action, ts DESC);
CREATE INDEX audit_events_actor_idx ON audit_events (actor_id, ts DESC);
CREATE INDEX audit_events_target_idx ON audit_events (target_kind, target_id, ts DESC);

-- Periodic signed checkpoints, so a verifier can start from a known-good
-- point instead of replaying the whole stream, and so retention can cut
-- the chain without destroying its verifiability.
CREATE TABLE audit_anchors (
    seq        bigint PRIMARY KEY,
    hash       bytea NOT NULL,
    kind       text NOT NULL DEFAULT 'checkpoint' CHECK (kind IN ('checkpoint', 'retention_cut')),
    signature  text,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Where a copy of the stream is shipped. The cursor makes delivery
-- at-least-once across restarts.
CREATE TABLE audit_exporters (
    id                   text PRIMARY KEY,
    organization_id      text REFERENCES organizations ON DELETE CASCADE,
    kind                 text NOT NULL CHECK (kind IN ('webhook')),
    config_enc           bytea NOT NULL,
    filter               jsonb,
    enabled              boolean NOT NULL DEFAULT true,
    cursor_seq           bigint NOT NULL DEFAULT 0,
    last_ok_at           timestamptz,
    last_error           text,
    consecutive_failures int NOT NULL DEFAULT 0,
    created_at           timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
-- Readable by its tenant; never writable or erasable through the app role.
CREATE POLICY org_isolation ON audit_events FOR SELECT USING (organization_id = current_org());

ALTER TABLE audit_exporters ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_exporters FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON audit_exporters USING (organization_id = current_org()) WITH CHECK (organization_id = current_org());

GRANT SELECT ON audit_events, audit_anchors TO supermcp_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_exporters TO supermcp_app;
-- Appending is the writer's job and runs as the maintenance role, so a bug
-- in a request handler cannot forge or rewrite history.
REVOKE INSERT, UPDATE, DELETE ON audit_events FROM supermcp_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_exporters, audit_anchors, audit_events;
-- +goose StatementEnd
