-- +goose Up
-- +goose StatementBegin

-- Registration used to create the user and organisation in one
-- transaction, record the first password in a second and bind the owner
-- role in a third. When either of the later two failed, the account and
-- its organisation stayed without an owner, and on a closed instance the
-- person could not try again because registration was now closed. This
-- overload of auth_register does all three in the one call.
--
-- Additive: the seven- and eight-argument auth_register stay as they
-- were, because pods of the previous release call them during a rolling
-- upgrade. They go in a later release, once no running version calls
-- them.
--
-- It also binds the missing owner in organisations the old code left
-- without one (auth_repair_orphan_owners, below). That only inserts rows.

-- auth_register with p_binding_id decides and creates the user and, when
-- p_org_id is set, their organisation, as the eight-argument version
-- does (migration 00035: the lock (21063, 0), the READ COMMITTED guard,
-- SQLSTATE SM001 when registration is closed and an account exists, and
-- lock_timeout). It then records p_password_hash in the password history
-- through auth_password_record, as auth_invite_accept does, so the first
-- password counts against a reuse policy, and binds the user to role_owner on the organisation with
-- p_binding_id as the binding's id. Any failure undoes all of it.
--
-- It repeats the eight-argument body rather than calling it, so dropping
-- that one later does not break this one.
CREATE OR REPLACE FUNCTION auth_register(p_user_id text, p_email text, p_name text, p_password_hash text,
                                         p_org_id text, p_org_slug text, p_org_name text,
                                         p_open_registration boolean, p_binding_id text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public SET lock_timeout = '5s' AS $f$
BEGIN
    IF NOT p_open_registration THEN
        IF current_setting('transaction_isolation') <> 'read committed' THEN
            RAISE EXCEPTION 'auth_register needs READ COMMITTED, not %', current_setting('transaction_isolation');
        END IF;
        PERFORM pg_advisory_xact_lock(21063, 0);
        IF EXISTS (SELECT 1 FROM users) THEN
            RAISE EXCEPTION 'registration is closed' USING ERRCODE = 'SM001';
        END IF;
    END IF;
    INSERT INTO users (id, email, name, password_hash) VALUES (p_user_id, p_email, p_name, p_password_hash);
    IF p_password_hash IS NOT NULL THEN
        PERFORM auth_password_record(p_user_id, p_password_hash);
    END IF;
    IF p_org_id IS NOT NULL THEN
        INSERT INTO organizations (id, slug, name) VALUES (p_org_id, p_org_slug, p_org_name);
        INSERT INTO organization_members (user_id, organization_id) VALUES (p_user_id, p_org_id);
        INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id, created_by)
        VALUES (p_binding_id, p_org_id, 'user', p_user_id, 'role_owner', p_user_id);
    END IF;
END
$f$;

REVOKE ALL ON FUNCTION auth_register(text, text, text, text, text, text, text, boolean, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_register(text, text, text, text, text, text, text, boolean, text) TO supermcp_app;

-- auth_repair_orphan_owners binds the owner role that the earlier
-- three-transaction registration failed to bind, and returns how many
-- bindings it made. An organisation is repaired only when all of these
-- hold, which together say registration made it and then failed:
--
--   - it has no role_owner binding;
--   - it has exactly one member, who is active;
--   - that member joined in the transaction that created the
--     organisation: both rows take now(), the transaction's start time,
--     so their created_at are equal. An invited member joins later, so
--     an organisation whose owner's account was erased does not hand
--     ownership to whoever is left.
--
-- The binding is the one registration writes: the member binds
-- themselves, organisation-wide. A second call finds nothing to do.
-- Only the migration and an operator call it; the application role
-- cannot.
CREATE OR REPLACE FUNCTION auth_repair_orphan_owners()
RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    WITH orphans AS (
        SELECT o.id AS organization_id, min(m.user_id) AS user_id
        FROM organizations o
        JOIN organization_members m ON m.organization_id = o.id
        WHERE NOT EXISTS (SELECT 1 FROM role_bindings b
                          WHERE b.organization_id = o.id AND b.role_id = 'role_owner')
        GROUP BY o.id, o.created_at
        HAVING count(*) = 1
           AND bool_and(m.deactivated_at IS NULL)
           AND bool_and(m.created_at = o.created_at)
    ), bound AS (
        INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id, created_by)
        SELECT gen_random_uuid()::text, organization_id, 'user', user_id, 'role_owner', user_id FROM orphans
        RETURNING 1
    )
    SELECT count(*)::integer FROM bound
$f$;

REVOKE ALL ON FUNCTION auth_repair_orphan_owners() FROM PUBLIC;

SELECT auth_repair_orphan_owners();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- The bindings the repair made stay: they are what registration should
-- have written.
DROP FUNCTION IF EXISTS auth_repair_orphan_owners(),
    auth_register(text, text, text, text, text, text, text, boolean, text);
-- +goose StatementEnd
