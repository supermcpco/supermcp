-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Approvals
--
-- A model holding a valid key can already do everything its role allows.
-- What an organisation wants before that key can refund a payment is a
-- person agreeing to this particular call, with these particular
-- arguments. Two tables: the standing rules, and one row per call that a
-- rule stopped.

-- approval_policies says which calls need a person.
--
-- scope_kind and scope_id are the four places a rule can be hung: the
-- whole organisation, one MCP server, one connector, one tool. The most
-- specific rule that matches a call governs it, so an organisation can
-- require approval for every destructive tool and then exempt the one
-- connector that only ever talks to a sandbox. That is what effect is
-- for: without 'allow' there would be no way to narrow a rule, only ways
-- to add more.
--
-- conditions is `json`, not `jsonb`, for the same reason the revisions
-- snapshot is: what comes back should be what was written, in the order
-- it was written, so a policy screen shows the rule an administrator
-- typed rather than a normalised rewrite of it.
CREATE TABLE approval_policies (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    name            text NOT NULL,
    scope_kind      text NOT NULL CHECK (scope_kind IN ('organization', 'server', 'connector', 'tool')),
    scope_id        text NOT NULL DEFAULT '',
    -- 'destructive' catches every tool annotated as changing state,
    -- 'tool' one tool by name, 'condition' a call whose arguments match.
    trigger_kind    text NOT NULL CHECK (trigger_kind IN ('destructive', 'tool', 'condition')),
    tool_name       text NOT NULL DEFAULT '',
    conditions      json,
    effect          text NOT NULL DEFAULT 'require' CHECK (effect IN ('require', 'allow')),
    -- How long the answer has, and then how long the answer is good for.
    ttl_seconds     int NOT NULL DEFAULT 3600 CHECK (ttl_seconds BETWEEN 60 AND 604800),
    enabled         boolean NOT NULL DEFAULT true,
    created_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT approval_policy_scope_named CHECK (scope_kind = 'organization' OR scope_id <> ''),
    CONSTRAINT approval_policy_tool_named CHECK (trigger_kind <> 'tool' OR tool_name <> ''),
    CONSTRAINT approval_policy_has_conditions CHECK (trigger_kind <> 'condition' OR conditions IS NOT NULL)
);

-- Every gated call reads this set, so it is read far more often than it
-- is written. Disabled policies are left out of the index: a rule that is
-- off should cost nothing to skip.
CREATE INDEX approval_policies_org_idx ON approval_policies (organization_id) WHERE enabled;

-- approval_requests is one call waiting on a person.
--
-- args_enc holds the arguments sealed under the organisation's data key,
-- exactly as a connector's credentials are. Storing them in the clear
-- would put the most sensitive thing about the call — the account number,
-- the amount, the address — in the one table an operator browses all day,
-- and the whole reason this call is worth approving is that its arguments
-- are worth reading. They are sealed rather than digested because an
-- approved request has to be replayable: what runs the second time has to
-- be what a person agreed to, not what the model asks for again.
--
-- There is deliberately no digest of the arguments beside the ciphertext.
-- A digest is a confirmable guess for anything low-entropy — an amount, a
-- customer id — and would hand back to whoever dumps this table most of
-- what sealing the column was for.
--
-- No foreign key to tools, connectors or servers: the record of what
-- someone approved is worth more than the tool it named, and outlives it.
CREATE TABLE approval_requests (
    id                text PRIMARY KEY,
    organization_id   text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    policy_id         text REFERENCES approval_policies ON DELETE SET NULL,
    policy_name       text NOT NULL DEFAULT '',   -- kept so a deleted policy still explains the request
    server_id         text NOT NULL DEFAULT '',
    connector_id      text NOT NULL DEFAULT '',
    tool_id           text NOT NULL,
    tool_name         text NOT NULL,
    requested_by      text NOT NULL,
    requester_kind    text NOT NULL DEFAULT 'user',
    requester_display text NOT NULL DEFAULT '',
    args_enc          bytea NOT NULL,
    -- Nobody answered, somebody refused, and somebody withdrew it are
    -- three different histories. An absence would record them as one.
    state             text NOT NULL DEFAULT 'pending'
                      CHECK (state IN ('pending', 'approved', 'rejected', 'expired', 'cancelled', 'consumed')),
    created_at        timestamptz NOT NULL DEFAULT now(),
    -- While pending this is the deadline for someone to answer. Once
    -- approved it is the deadline for the call to be replayed, moved
    -- forward by the same ttl: an approval granted a minute before the
    -- question went stale would otherwise be useless.
    expires_at        timestamptz NOT NULL,
    ttl_seconds       int NOT NULL DEFAULT 3600 CHECK (ttl_seconds > 0),
    decided_by        text,
    decided_at        timestamptz,
    cancelled_at      timestamptz,
    consumed_at       timestamptz,
    reason            text NOT NULL DEFAULT '',   -- why it was approved, refused, or withdrawn
    -- Nobody approves their own refund. This is a constraint rather than a
    -- rule in the service because it is the one property of the whole
    -- feature that must hold however the row was written.
    CONSTRAINT approval_not_self_decided CHECK (decided_by IS NULL OR decided_by <> requested_by),
    CONSTRAINT approval_decided_together CHECK ((decided_by IS NULL) = (decided_at IS NULL)),
    CONSTRAINT approval_decided_states CHECK (
        state NOT IN ('approved', 'rejected', 'consumed') OR decided_by IS NOT NULL),
    CONSTRAINT approval_cancelled_dated CHECK (state <> 'cancelled' OR cancelled_at IS NOT NULL),
    CONSTRAINT approval_consumed_dated CHECK (state <> 'consumed' OR consumed_at IS NOT NULL)
);

-- The queue a person works through.
CREATE INDEX approval_requests_pending_idx
    ON approval_requests (organization_id, created_at DESC) WHERE state = 'pending';
-- The replay lookup: this caller's answered request for this tool.
CREATE INDEX approval_requests_replay_idx
    ON approval_requests (organization_id, tool_id, requested_by, created_at DESC)
    WHERE state IN ('pending', 'approved', 'rejected');
-- The sweep that turns unanswered into expired.
CREATE INDEX approval_requests_expiry_idx ON approval_requests (expires_at) WHERE state = 'pending';

ALTER TABLE approval_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON approval_policies
    USING (organization_id = current_org()) WITH CHECK (organization_id = current_org());

ALTER TABLE approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON approval_requests
    USING (organization_id = current_org()) WITH CHECK (organization_id = current_org());

GRANT SELECT, INSERT, UPDATE, DELETE ON approval_policies TO supermcp_app;

-- 00002 grants the application everything on every new table by default,
-- which here would let the process that runs the call rewrite the
-- arguments a person has already approved. Take it back and hand out only
-- the columns a transition moves: the request as it was asked for is
-- fixed once it is written, and a decision is a record, so there is no
-- DELETE either.
REVOKE ALL ON approval_requests FROM supermcp_app;
GRANT SELECT, INSERT ON approval_requests TO supermcp_app;
GRANT UPDATE (state, expires_at, decided_by, decided_at, cancelled_at, consumed_at, reason)
    ON approval_requests TO supermcp_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS approval_requests;
DROP TABLE IF EXISTS approval_policies;
-- +goose StatementEnd
