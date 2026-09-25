-- +goose Up
-- +goose StatementBegin

-- The authorisation evaluator grants nothing to a deactivated member: it
-- reads organization_members.deactivated_at next to the role bindings. The
-- triggers of 00020_cache_invalidation.sql did not cover that table, so a
-- deactivation dropped only the writing replica's cached grants and the
-- member kept working on the others until their copy aged out.
--
-- This trigger sends 'authz:<organization id>' on the supermcp_cache
-- channel when a membership is added, removed (directly or by a cascade
-- from its user or organisation), or deactivated or reactivated.
--
-- Its own function rather than 00020's: that one treats any column change
-- as news, and here only deactivated_at and the key are read by the
-- evaluator. A membership row always belongs to an organisation, so there
-- is no '*' payload.
--
-- Additive only: an older replica during a rolling upgrade does not listen
-- and is unaffected; it keeps its thirty-second expiry.

CREATE OR REPLACE FUNCTION supermcp_member_cache_notify() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $f$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.deactivated_at IS NOT DISTINCT FROM NEW.deactivated_at
       AND OLD.user_id = NEW.user_id
       AND OLD.organization_id = NEW.organization_id THEN
        -- A no-op update, such as re-activating an active member through
        -- ON CONFLICT DO UPDATE, changes nothing the evaluator reads.
        RETURN NULL;
    END IF;
    IF TG_OP <> 'INSERT' THEN
        PERFORM pg_notify('supermcp_cache', 'authz:' || OLD.organization_id);
    END IF;
    IF TG_OP = 'INSERT' OR (TG_OP = 'UPDATE' AND NEW.organization_id <> OLD.organization_id) THEN
        PERFORM pg_notify('supermcp_cache', 'authz:' || NEW.organization_id);
    END IF;
    RETURN NULL;
END
$f$;

CREATE OR REPLACE TRIGGER supermcp_member_cache_notify
    AFTER INSERT OR UPDATE OF deactivated_at, user_id, organization_id OR DELETE ON organization_members
    FOR EACH ROW EXECUTE FUNCTION supermcp_member_cache_notify();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS supermcp_member_cache_notify ON organization_members;
DROP FUNCTION IF EXISTS supermcp_member_cache_notify();
-- +goose StatementEnd
