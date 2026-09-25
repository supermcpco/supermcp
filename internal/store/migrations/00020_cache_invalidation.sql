-- +goose Up
-- +goose StatementBegin

-- Every replica caches, for up to thirty seconds, what the authorisation
-- evaluator and the data-loss policy reader last read. A write dropped
-- only the writing replica's copy, so a revoked role went on working on
-- the others until their copy aged out.
--
-- These triggers tell every replica instead. Each change to a table one of
-- those caches reads sends a notification on the supermcp_cache channel
-- (internal/invalidation.Channel) naming the cache and the organisation:
-- 'authz:<organization id>' or 'dlp:<organization id>', and '<kind>:*' for
-- a row that belongs to no organisation, such as a built-in role. Each
-- replica holds a LISTEN connection and drops that organisation's entries.
--
-- Triggers rather than a call in each service, because the writes to these
-- tables come from many places — the roles API, sign-in through an
-- identity provider, SCIM, service accounts, tool deletion — and from
-- foreign-key cascades (deleting a role removes its bindings and access
-- rules; deleting a connector or tool removes its data-loss policies) that
-- no service code sees. Row triggers fire for cascaded rows too.
--
-- pg_notify inside a transaction is delivered only on commit, and
-- identical payloads within one transaction are delivered once, so a bulk
-- change costs one notification per organisation, not one per row.
--
-- The function is not SECURITY DEFINER: it only calls pg_notify, which
-- every role may, and it runs as whoever made the change. search_path is
-- pinned so nothing the caller has on theirs can stand in for pg_notify.
--
-- Additive only: an older replica during a rolling upgrade does not listen
-- and is unaffected; it keeps its thirty-second expiry.

CREATE OR REPLACE FUNCTION supermcp_cache_notify() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $f$
DECLARE
    kind    text := TG_ARGV[0];
    old_org text;
    new_org text;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        -- A no-op update (every column the same) changes nothing cached.
        IF OLD IS NOT DISTINCT FROM NEW THEN
            RETURN NULL;
        END IF;
    END IF;
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        old_org := OLD.organization_id;
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        new_org := NEW.organization_id;
    END IF;
    IF TG_OP <> 'INSERT' THEN
        PERFORM pg_notify('supermcp_cache', kind || ':' || COALESCE(old_org, '*'));
    END IF;
    IF TG_OP = 'INSERT' OR (TG_OP = 'UPDATE' AND new_org IS DISTINCT FROM old_org) THEN
        PERFORM pg_notify('supermcp_cache', kind || ':' || COALESCE(new_org, '*'));
    END IF;
    RETURN NULL;
END
$f$;

-- What the authorisation evaluator reads: a principal's bindings joined to
-- their roles' permissions, and the organisation's tool access rules.
CREATE OR REPLACE TRIGGER supermcp_cache_notify
    AFTER INSERT OR UPDATE OR DELETE ON role_bindings
    FOR EACH ROW EXECUTE FUNCTION supermcp_cache_notify('authz');

CREATE OR REPLACE TRIGGER supermcp_cache_notify
    AFTER INSERT OR UPDATE OR DELETE ON roles
    FOR EACH ROW EXECUTE FUNCTION supermcp_cache_notify('authz');

CREATE OR REPLACE TRIGGER supermcp_cache_notify
    AFTER INSERT OR UPDATE OR DELETE ON tool_access_rules
    FOR EACH ROW EXECUTE FUNCTION supermcp_cache_notify('authz');

-- What the data-loss policy reader reads.
CREATE OR REPLACE TRIGGER supermcp_cache_notify
    AFTER INSERT OR UPDATE OR DELETE ON dlp_policies
    FOR EACH ROW EXECUTE FUNCTION supermcp_cache_notify('dlp');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS supermcp_cache_notify ON dlp_policies;
DROP TRIGGER IF EXISTS supermcp_cache_notify ON tool_access_rules;
DROP TRIGGER IF EXISTS supermcp_cache_notify ON roles;
DROP TRIGGER IF EXISTS supermcp_cache_notify ON role_bindings;
DROP FUNCTION IF EXISTS supermcp_cache_notify();
-- +goose StatementEnd
