-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Data-loss prevention
--
-- A tool call can carry a customer's card number, a national identifier or
-- a credential out to an upstream, or back into a model's context. These
-- two tables hold what an organisation has decided about that, and what
-- happened when the decision was applied.
--
-- The masking in internal/audit stays where it is: it is the floor that
-- keeps a card number out of the record when nobody has configured
-- anything. These policies sit above it and act on the call itself.

-- One rule per scope. A policy with no connector covers the organisation;
-- one with a connector covers that connector; one with a tool covers that
-- tool, and replaces the two broader rules rather than adding to them.
--
-- The unique index below is the reason resolution is predictable: a scope
-- has exactly one rule, so there is never a question of which of two
-- policies an administrator meant. The cost is that a scope cannot both
-- mask cards and refuse credentials — it takes one action for the
-- detectors it names — and that is a trade we make deliberately, because
-- a resolution nobody can predict is worse than a rule that has to be
-- written twice at two scopes.
CREATE TABLE dlp_policies (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    name            text NOT NULL,
    -- Scope. A tool-scoped policy names its connector too, so the three
    -- levels are ordered by inspection.
    connector_id    text REFERENCES connectors ON DELETE CASCADE,
    tool_id         text REFERENCES tools ON DELETE CASCADE,
    -- Which half of a call to scan.
    scan            text NOT NULL DEFAULT 'both' CHECK (scan IN ('arguments', 'result', 'both')),
    -- Which detectors run. Empty means every built-in; the names are the
    -- constants in internal/dlp, which are added to but never renamed.
    detectors       text[] NOT NULL DEFAULT '{}',
    action          text NOT NULL CHECK (action IN ('allow', 'mask', 'refuse')),
    enabled         boolean NOT NULL DEFAULT true,
    -- How much of a value to read. Zero takes the built-in cap, which is
    -- what almost every organisation should leave it at: the number exists
    -- so a payments system can pay for a larger window on the request path
    -- without every other tenant paying for it too.
    max_bytes       int NOT NULL DEFAULT 0 CHECK (max_bytes >= 0 AND max_bytes <= 4194304),
    created_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX dlp_policies_org_idx ON dlp_policies (organization_id) WHERE enabled;
CREATE UNIQUE INDEX dlp_policies_scope_idx
    ON dlp_policies (organization_id, COALESCE(connector_id, ''), COALESCE(tool_id, ''));

-- What a scan found.
--
-- Does storing a finding store the very thing it found? It must not, and
-- here it does not. A row says which detector fired, which of its rules,
-- how confident it was, how many times it matched and which fields it
-- matched in — and nothing else. There is no excerpt, no prefix, no last
-- four digits and no hash.
--
-- A hash is the tempting one, because it would let two findings be
-- compared without either being readable. It is refused anyway: a card
-- number is sixteen digits and a national identifier is fewer, so the
-- whole input space of either can be enumerated against a hash in minutes
-- on a laptop. A keyed hash would resist that, and would then need a key
-- with a rotation story, a place to live and a reason to exist — all to
-- answer a question the organisation has not asked.
--
-- What remains is metadata. A field name such as $.customer.card is the
-- shape of the request, not the customer; byte offsets are not stored at
-- all, since they are only useful against a copy of the text and the only
-- copy is the audit payload, which has its own policy about whether it
-- exists. A reader of this table learns that a payments tool returned
-- eleven card numbers last Tuesday, and cannot learn one of them.
CREATE TABLE dlp_findings (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    -- No foreign key to tool_invocations: invocations are pruned on their
    -- own schedule, and a finding outliving the row it points at is worth
    -- more than a cascade that deletes the evidence with the log line.
    invocation_id   text,
    policy_id       text REFERENCES dlp_policies ON DELETE SET NULL,
    connector_id    text,
    tool_id         text,
    tool_name       text NOT NULL DEFAULT '',
    stage           text NOT NULL CHECK (stage IN ('arguments', 'result')),
    action          text NOT NULL CHECK (action IN ('allow', 'mask', 'refuse')),
    detector        text NOT NULL,
    rule            text NOT NULL DEFAULT '',
    kind            text NOT NULL,
    confidence      text NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    matches         int NOT NULL DEFAULT 1,
    -- Where, by field name. Capped by the writer, not by a constraint.
    paths           text[] NOT NULL DEFAULT '{}',
    -- The scan stopped at its byte budget, so this row is what was seen
    -- and not necessarily what was there.
    truncated       boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX dlp_findings_org_time_idx ON dlp_findings (organization_id, created_at DESC);
CREATE INDEX dlp_findings_tool_idx ON dlp_findings (organization_id, tool_id, created_at DESC);
CREATE INDEX dlp_findings_invocation_idx ON dlp_findings (invocation_id);

-- ---------------------------------------------------------------------------
-- Row-level security

ALTER TABLE dlp_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE dlp_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON dlp_policies
    USING (organization_id = current_org()) WITH CHECK (organization_id = current_org());

ALTER TABLE dlp_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE dlp_findings FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON dlp_findings
    USING (organization_id = current_org()) WITH CHECK (organization_id = current_org());

GRANT SELECT, INSERT, UPDATE, DELETE ON dlp_policies TO supermcp_app;
-- Findings are append-only through the app role, as audit_events are: a
-- request handler writes them and nothing in a request path has a reason
-- to edit or erase one. Retention runs as the maintenance role.
GRANT SELECT, INSERT ON dlp_findings TO supermcp_app;

-- No SECURITY DEFINER function here, unlike 00005 and 00010. Those exist
-- for lookups that happen before a tenant is known; every read and write
-- below happens inside a request that already has one, so the tenant
-- policy above is the whole of the access control.

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS dlp_findings, dlp_policies;
-- +goose StatementEnd
