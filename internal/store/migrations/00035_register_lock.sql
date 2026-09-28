-- +goose Up
-- +goose StatementBegin

-- Registration used to count users in one transaction and create the
-- account in another. Two sign-ups arriving together on an unclaimed
-- instance with open registration off both counted none and both
-- succeeded. This overload of auth_register decides and inserts in one
-- transaction, under a lock every registration takes while registration
-- is closed, so the second one sees the first and is refused.
--
-- Additive: the seven-argument auth_register stays as it was, because
-- pods of the previous release call it during a rolling upgrade. It goes
-- in a later release, once no running version calls it.

-- auth_users_exist reports whether any account exists. The anonymous
-- session asks it on every call, so it stops at the first row where
-- auth_user_count reads them all.
CREATE OR REPLACE FUNCTION auth_users_exist()
RETURNS boolean LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT EXISTS (SELECT 1 FROM users)
$f$;

-- auth_register with p_open_registration creates the user and, when
-- p_org_id is set, their organisation, as the seven-argument version
-- does. When p_open_registration is false and an account already exists
-- it raises SQLSTATE SM001 (registration closed) and creates nothing.
--
-- With registration closed it first takes the transaction-scoped advisory
-- lock (21063, 0): class 21063 is 0x5247, "RG", beside the classes
-- internal/governance uses, and out of the single-key space. The function
-- is volatile, so under READ COMMITTED the EXISTS below takes a snapshot
-- after the lock is granted and sees a registration that committed while
-- this one waited. Under REPEATABLE READ or SERIALIZABLE the snapshot is
-- older than the lock and the race is back, so any other isolation level
-- is refused outright. An open instance takes no lock and does not
-- serialise sign-ups.
--
-- lock_timeout bounds the wait; running out raises lock_not_available
-- (55P03), an ordinary failure rather than a refusal. The SET clause
-- restores the caller's value when the function returns.
CREATE OR REPLACE FUNCTION auth_register(p_user_id text, p_email text, p_name text, p_password_hash text,
                                         p_org_id text, p_org_slug text, p_org_name text,
                                         p_open_registration boolean)
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
    IF p_org_id IS NOT NULL THEN
        INSERT INTO organizations (id, slug, name) VALUES (p_org_id, p_org_slug, p_org_name);
        INSERT INTO organization_members (user_id, organization_id) VALUES (p_user_id, p_org_id);
    END IF;
END
$f$;

REVOKE ALL ON FUNCTION auth_users_exist(),
    auth_register(text, text, text, text, text, text, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_users_exist(),
    auth_register(text, text, text, text, text, text, text, boolean) TO supermcp_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS auth_register(text, text, text, text, text, text, text, boolean), auth_users_exist();
-- +goose StatementEnd
