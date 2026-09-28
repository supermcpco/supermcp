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

-- auth_register with p_binding_id decides and creates the user and, when
-- p_org_id is set, their organisation, as the eight-argument version
-- does (migration 00035: the lock (21063, 0), the READ COMMITTED guard,
-- SQLSTATE SM001 when registration is closed and an account exists, and
-- lock_timeout). It then records p_password_hash in the password history,
-- as auth_password_record does, so the first password counts against a
-- reuse policy, and binds the user to role_owner on the organisation with
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
        INSERT INTO password_history (user_id, hash) VALUES (p_user_id, p_password_hash) ON CONFLICT DO NOTHING;
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

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS auth_register(text, text, text, text, text, text, text, boolean, text);
-- +goose StatementEnd
