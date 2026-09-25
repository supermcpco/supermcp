-- +goose NO TRANSACTION
-- +goose Up

-- An authorization code and the refresh tokens it leads to remember the
-- browser session that consented (session_id) and how that session
-- authenticated (amr, RFC 8176 values), so that ending the session ends
-- the tokens it granted, and a token can say how its holder signed in. A
-- client_credentials grant has no session and stores neither.
--
-- Additive. A replica of the previous release inserts codes and refresh
-- tokens without the new columns, so session_id stays NULL, and it calls
-- auth_session_revoke, auth_session_revoke_others and
-- auth_revoke_principal by their old signatures, which are kept and now
-- do what their replacements below do.
--
-- NO TRANSACTION for the batched backfill and the concurrent index
-- builds, neither of which can run inside one transaction. Every
-- statement is safe to run again if the migration is interrupted.
--
-- Columns are added with a constant default or none, which is a
-- catalogue change only: no row is rewritten, and the ACCESS EXCLUSIVE
-- lock is held for that change alone.
ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS session_id text;
ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS amr text[] NOT NULL DEFAULT '{}';
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS session_id text;
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS amr text[] NOT NULL DEFAULT '{}';

-- A session's id is the digest of its cookie secret and is what every
-- auth_session_* function takes, so it does not leave the server. The
-- public id is what a token's sid claim and the sessions list show. It is
-- random, not derived, so it says nothing about the id. The column is
-- added bare and given its default afterwards, so adding it does not
-- rewrite the table; rows from before are filled in batches below, and
-- rows an older replica inserts meanwhile get the default.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS public_id text;
ALTER TABLE sessions ALTER COLUMN public_id SET DEFAULT gen_random_uuid()::text;

-- Batches of 1000 by id, each committed on its own, so a request touching
-- a session waits for one batch at most, never for the whole table.
-- +goose StatementBegin
DO $$
DECLARE
    after text := '';
    upto  text;
BEGIN
    LOOP
        SELECT max(b.id) INTO upto
        FROM (SELECT id FROM sessions WHERE id > after ORDER BY id LIMIT 1000) b;
        EXIT WHEN upto IS NULL;
        UPDATE sessions SET public_id = gen_random_uuid()::text
        WHERE id > after AND id <= upto AND public_id IS NULL;
        after := upto;
        COMMIT;
    END LOOP;
END
$$;
-- +goose StatementEnd

-- CONCURRENTLY so neither build blocks sign-ins or token issuance. A
-- failed concurrent build leaves an invalid index under the same name;
-- the DROP first makes a rerun rebuild it rather than skip it.
DROP INDEX CONCURRENTLY IF EXISTS sessions_public_id_idx;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS sessions_public_id_idx ON sessions (public_id);
-- Ending a session finds its refresh tokens through this index.
DROP INDEX CONCURRENTLY IF EXISTS oauth_refresh_session_idx;
CREATE INDEX CONCURRENTLY IF NOT EXISTS oauth_refresh_session_idx
    ON oauth_refresh_tokens (session_id) WHERE session_id IS NOT NULL;

-- The functions below end a session's refresh tokens by family, not by
-- session_id alone: a replica of the previous release rotates a token
-- into a child without a session_id, and the family is what still ties
-- that child to the session.
--
-- Each is plpgsql and runs its statements one after another, each with a
-- snapshot of its own. The token endpoint holds a share lock on the
-- session row while it rotates a token, so the UPDATE of the session
-- waits for a rotation in flight, and the UPDATE of the tokens that
-- follows sees the child it inserted. One statement with a CTE would not:
-- its snapshot predates the wait.
--
-- Each returns how many live refresh tokens it revoked, one per client
-- the sessions had connected, for the audit trail.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth_session_end(p_id text, p_reason text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
DECLARE
    n integer;
BEGIN
    UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason WHERE id = p_id AND revoked_at IS NULL;
    WITH r AS (
        UPDATE oauth_refresh_tokens SET revoked_at = now()
        WHERE revoked_at IS NULL
          AND family_id IN (SELECT family_id FROM oauth_refresh_tokens WHERE session_id = p_id)
        RETURNING consumed_at)
    SELECT count(*) FILTER (WHERE consumed_at IS NULL) INTO n FROM r;
    RETURN n;
END
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth_session_end_others(p_user text, p_keep text, p_reason text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
DECLARE
    ended text[];
    n     integer;
BEGIN
    WITH u AS (
        UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason
        WHERE user_id = p_user AND id <> p_keep AND revoked_at IS NULL
        RETURNING id)
    SELECT COALESCE(array_agg(id), '{}') INTO ended FROM u;
    WITH r AS (
        UPDATE oauth_refresh_tokens SET revoked_at = now()
        WHERE revoked_at IS NULL
          AND family_id IN (SELECT family_id FROM oauth_refresh_tokens WHERE session_id = ANY(ended))
        RETURNING consumed_at)
    SELECT count(*) FILTER (WHERE consumed_at IS NULL) INTO n FROM r;
    RETURN n;
END
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Deactivating a principal ends every session it has, in every
-- organisation, with the refresh tokens those sessions granted wherever
-- they were issued; and, as before, every API key and refresh token it
-- holds in this organisation.
CREATE OR REPLACE FUNCTION auth_principal_end(p_org text, p_user text, p_reason text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
DECLARE
    ended text[];
    n     integer;
    m     integer;
BEGIN
    WITH u AS (
        UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason
        WHERE user_id = p_user AND revoked_at IS NULL
        RETURNING id)
    SELECT COALESCE(array_agg(id), '{}') INTO ended FROM u;
    WITH r AS (
        UPDATE oauth_refresh_tokens SET revoked_at = now()
        WHERE revoked_at IS NULL
          AND family_id IN (SELECT family_id FROM oauth_refresh_tokens WHERE session_id = ANY(ended))
        RETURNING consumed_at)
    SELECT count(*) FILTER (WHERE consumed_at IS NULL) INTO n FROM r;
    UPDATE api_keys SET revoked_at = now(), revoked_reason = p_reason
    WHERE organization_id = p_org AND principal_kind = 'user' AND principal_id = p_user AND revoked_at IS NULL;
    WITH r AS (
        UPDATE oauth_refresh_tokens SET revoked_at = now()
        WHERE organization_id = p_org AND user_id = p_user AND revoked_at IS NULL
        RETURNING consumed_at)
    SELECT count(*) FILTER (WHERE consumed_at IS NULL) INTO m FROM r;
    RETURN n + m;
END
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
-- A re-authentication through a provider replaces a session with a new
-- one for the same person in the same organisation. The refresh tokens
-- the old session granted move to the new one, live, instead of ending
-- with it; then the old session ends. The old row is locked first, so a
-- rotation in flight finishes before the move and its child moves too.
-- If the two do not match, or the new session is not live, nothing moves
-- and the old session ends with its tokens.
CREATE OR REPLACE FUNCTION auth_session_replace(p_old text, p_new text, p_reason text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
DECLARE
    ok boolean;
BEGIN
    PERFORM 1 FROM sessions WHERE id = p_old FOR UPDATE;
    SELECT EXISTS (
        SELECT 1 FROM sessions o JOIN sessions n
          ON n.user_id = o.user_id AND n.organization_id = o.organization_id
        WHERE o.id = p_old AND o.revoked_at IS NULL
          AND n.id = p_new AND n.revoked_at IS NULL
          AND n.absolute_expires_at > now() AND n.idle_expires_at > now()) INTO ok;
    IF NOT ok THEN
        PERFORM auth_session_end(p_old, p_reason);
        RETURN;
    END IF;
    UPDATE oauth_refresh_tokens SET session_id = p_new
    WHERE revoked_at IS NULL
      AND family_id IN (SELECT family_id FROM oauth_refresh_tokens WHERE session_id = p_old);
    UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason WHERE id = p_old AND revoked_at IS NULL;
END
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Whether the session a token's sid names has ended. A session that is
-- no longer on record counts as ended: the pruner keeps an ended or
-- expired session while any live refresh token still names it, so a
-- missing row means nothing may use it.
CREATE OR REPLACE FUNCTION auth_session_ended(p_public text)
RETURNS boolean LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT COALESCE((SELECT s.revoked_at IS NOT NULL FROM sessions s WHERE s.public_id = p_public), true)
$f$;
-- +goose StatementEnd

-- The previous release's names, kept for replicas of it during the roll.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth_session_revoke(p_id text, p_reason text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
BEGIN
    PERFORM auth_session_end(p_id, p_reason);
END
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth_session_revoke_others(p_user text, p_keep text, p_reason text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
BEGIN
    PERFORM auth_session_end_others(p_user, p_keep, p_reason);
END
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth_revoke_principal(p_org text, p_user text, p_reason text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
BEGIN
    PERFORM auth_principal_end(p_org, p_user, p_reason);
END
$f$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION auth_session_end(text, text), auth_session_end_others(text, text, text),
    auth_principal_end(text, text, text), auth_session_replace(text, text, text),
    auth_session_ended(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_session_end(text, text), auth_session_end_others(text, text, text),
    auth_principal_end(text, text, text), auth_session_replace(text, text, text),
    auth_session_ended(text) TO supermcp_app;

-- +goose Down

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth_revoke_principal(p_org text, p_user text, p_reason text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
BEGIN
    UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason
    WHERE user_id = p_user AND revoked_at IS NULL;
    UPDATE api_keys SET revoked_at = now(), revoked_reason = p_reason
    WHERE organization_id = p_org AND principal_kind = 'user' AND principal_id = p_user AND revoked_at IS NULL;
    UPDATE oauth_refresh_tokens SET revoked_at = now()
    WHERE organization_id = p_org AND user_id = p_user AND revoked_at IS NULL;
END
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth_session_revoke_others(p_user text, p_keep text, p_reason text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason
    WHERE user_id = p_user AND id <> p_keep AND revoked_at IS NULL
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth_session_revoke(p_id text, p_reason text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason WHERE id = p_id AND revoked_at IS NULL
$f$;
-- +goose StatementEnd

DROP FUNCTION IF EXISTS auth_session_ended(text), auth_session_replace(text, text, text),
    auth_principal_end(text, text, text), auth_session_end_others(text, text, text),
    auth_session_end(text, text);
DROP INDEX CONCURRENTLY IF EXISTS oauth_refresh_session_idx;
DROP INDEX CONCURRENTLY IF EXISTS sessions_public_id_idx;
ALTER TABLE sessions DROP COLUMN IF EXISTS public_id;
ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS amr;
ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS session_id;
ALTER TABLE oauth_codes DROP COLUMN IF EXISTS amr;
ALTER TABLE oauth_codes DROP COLUMN IF EXISTS session_id;
