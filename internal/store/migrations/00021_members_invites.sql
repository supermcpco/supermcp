-- +goose Up
-- +goose StatementBegin

-- Invitations to join an organisation. An administrator creates one for an
-- email address and a role; the server returns a link carrying a random
-- token exactly once and keeps only its SHA-256 digest here. Nothing is
-- mailed: the administrator sends the link themselves.
--
-- An invite is pending while accepted_at and revoked_at are both NULL and
-- expires_at is in the future. The partial unique index allows one open
-- invite per address per organisation (an expired one still counts until
-- it is revoked, so the API revokes it before issuing a new one).
--
-- The person accepting has no session in the organisation yet, and may have
-- no account at all, so lookup and acceptance go through the two SECURITY
-- DEFINER functions below, in the same way auth_register does.
--
-- Additive only: an older replica during a rolling upgrade never reads the
-- table or calls the functions.

CREATE TABLE org_invites (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations ON DELETE CASCADE,
    email           text NOT NULL,
    email_lower     text GENERATED ALWAYS AS (lower(email)) STORED,
    role_id         text NOT NULL REFERENCES roles ON DELETE CASCADE,
    token_hash      bytea NOT NULL UNIQUE,
    invited_by      text,
    expires_at      timestamptz NOT NULL,
    accepted_at     timestamptz,
    accepted_by     text,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX org_invites_active_idx ON org_invites (organization_id, email_lower)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

ALTER TABLE org_invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_invites FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON org_invites
    USING (organization_id = current_org()) WITH CHECK (organization_id = current_org());

GRANT SELECT, INSERT, UPDATE, DELETE ON org_invites TO supermcp_app;

-- auth_invite_by_token returns the pending invite whose token digest is
-- p_hash, or no row when it is unknown, accepted, revoked or expired. The
-- caller cannot tell those apart, on purpose.
CREATE OR REPLACE FUNCTION auth_invite_by_token(p_hash bytea)
RETURNS TABLE (id text, organization_id text, org_name text, email text, role_id text, role_name text,
               expires_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $f$
    SELECT i.id, i.organization_id, o.name, i.email, i.role_id, r.name, i.expires_at
    FROM org_invites i
    JOIN organizations o ON o.id = i.organization_id
    JOIN roles r ON r.id = i.role_id
    WHERE i.token_hash = p_hash
      AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > now()
$f$;

-- auth_invite_accept consumes the pending invite whose token digest is
-- p_hash and makes a user a member of its organisation with its role.
--
-- p_existing_user is the signed-in user accepting it; their email must be
-- the invite's. When it is NULL a user is created from p_new_user_id,
-- p_email (which must be the invite's), p_name and p_password_hash, as
-- auth_register does, and the password goes into the history.
--
-- Returns one row (user_id, organization_id), or no row when the invite is
-- not pending, including when a concurrent call accepted it first: the row
-- is locked, so an invite is used once. An email that does not match
-- raises insufficient_privilege (42501); a new user whose email already
-- has an account raises unique_violation (23505).
CREATE OR REPLACE FUNCTION auth_invite_accept(p_hash bytea, p_existing_user text, p_new_user_id text,
                                              p_email text, p_name text, p_password_hash text,
                                              p_binding_id text)
RETURNS TABLE (user_id text, organization_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
DECLARE
    inv  org_invites%ROWTYPE;
    uid  text;
BEGIN
    SELECT * INTO inv FROM org_invites i
    WHERE i.token_hash = p_hash
      AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > now()
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    IF p_existing_user IS NOT NULL THEN
        SELECT u.id INTO uid FROM users u WHERE u.id = p_existing_user AND u.email_lower = inv.email_lower;
        IF uid IS NULL THEN
            RAISE EXCEPTION 'invite is for another email address' USING ERRCODE = '42501';
        END IF;
    ELSE
        IF lower(p_email) IS DISTINCT FROM inv.email_lower THEN
            RAISE EXCEPTION 'invite is for another email address' USING ERRCODE = '42501';
        END IF;
        INSERT INTO users (id, email, name, password_hash) VALUES (p_new_user_id, p_email, p_name, p_password_hash);
        IF p_password_hash IS NOT NULL THEN
            PERFORM auth_password_record(p_new_user_id, p_password_hash);
        END IF;
        uid := p_new_user_id;
    END IF;

    INSERT INTO organization_members (user_id, organization_id) VALUES (uid, inv.organization_id)
    ON CONFLICT ON CONSTRAINT organization_members_pkey DO UPDATE SET deactivated_at = NULL;

    INSERT INTO role_bindings (id, organization_id, principal_kind, principal_id, role_id, scope_kind, source, created_by)
    VALUES (p_binding_id, inv.organization_id, 'user', uid, inv.role_id, 'org', 'invite', inv.invited_by)
    ON CONFLICT DO NOTHING;

    UPDATE org_invites SET accepted_at = now(), accepted_by = uid WHERE org_invites.id = inv.id;

    user_id := uid;
    organization_id := inv.organization_id;
    RETURN NEXT;
END
$f$;

REVOKE ALL ON FUNCTION auth_invite_by_token(bytea),
    auth_invite_accept(bytea, text, text, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_invite_by_token(bytea),
    auth_invite_accept(bytea, text, text, text, text, text, text) TO supermcp_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS auth_invite_accept(bytea, text, text, text, text, text, text), auth_invite_by_token(bytea);
DROP TABLE IF EXISTS org_invites;
-- +goose StatementEnd
