-- +goose NO TRANSACTION
-- +goose Up

-- An authorization code and the refresh tokens it leads to remember the
-- browser session that consented (session_id, the sid claim) and how that
-- session authenticated (amr, RFC 8176 values), so that ending the session
-- can end the tokens it issued, and a token can say how its holder signed
-- in. A client_credentials grant has no session and stores neither.
--
-- Additive. A replica of the previous release inserts codes and refresh
-- tokens without the new columns: session_id stays NULL, and those tokens
-- are tied to no session, as every token was before. It calls the
-- functions below by their old signatures, which are unchanged.
--
-- NO TRANSACTION for the concurrent index build, which cannot run inside
-- a transaction. Every statement is safe to run again.
--
-- The columns are added with a constant default or none, which is a
-- catalogue change only: no row is rewritten, and the ACCESS EXCLUSIVE
-- lock is held for that change alone.
ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS session_id text;
ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS amr text[] NOT NULL DEFAULT '{}';
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS session_id text;
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS amr text[] NOT NULL DEFAULT '{}';

-- Ending a session finds its refresh tokens through this index.
-- CONCURRENTLY so the build does not block token issuance. A failed
-- concurrent build leaves an invalid index under the same name; the DROP
-- first makes a rerun rebuild it rather than skip it.
DROP INDEX CONCURRENTLY IF EXISTS oauth_refresh_session_idx;
CREATE INDEX CONCURRENTLY IF NOT EXISTS oauth_refresh_session_idx
    ON oauth_refresh_tokens (session_id) WHERE session_id IS NOT NULL;

-- +goose StatementBegin
-- Ending one session ends the refresh tokens it consented to.
CREATE OR REPLACE FUNCTION auth_session_revoke(p_id text, p_reason text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
BEGIN
    UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason WHERE id = p_id AND revoked_at IS NULL;
    UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE session_id = p_id AND revoked_at IS NULL;
END
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth_session_revoke_others(p_user text, p_keep text, p_reason text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    WITH ended AS (
        UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason
        WHERE user_id = p_user AND id <> p_keep AND revoked_at IS NULL
        RETURNING id)
    UPDATE oauth_refresh_tokens SET revoked_at = now()
    WHERE session_id IN (SELECT id FROM ended) AND revoked_at IS NULL
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Deactivating a principal ends every session it has, in every
-- organisation, and with them the refresh tokens those sessions consented
-- to wherever they were issued; and, as before, every refresh token and
-- API key it holds in this organisation.
CREATE OR REPLACE FUNCTION auth_revoke_principal(p_org text, p_user text, p_reason text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
BEGIN
    WITH ended AS (
        UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason
        WHERE user_id = p_user AND revoked_at IS NULL
        RETURNING id)
    UPDATE oauth_refresh_tokens SET revoked_at = now()
    WHERE session_id IN (SELECT id FROM ended) AND revoked_at IS NULL;
    UPDATE api_keys SET revoked_at = now(), revoked_reason = p_reason
    WHERE organization_id = p_org AND principal_kind = 'user' AND principal_id = p_user AND revoked_at IS NULL;
    UPDATE oauth_refresh_tokens SET revoked_at = now()
    WHERE organization_id = p_org AND user_id = p_user AND revoked_at IS NULL;
END
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
-- A re-authentication through a provider replaces the session with a new
-- one for the same person. The refresh tokens the old session consented to
-- move to the new one, live, instead of ending with it; then the old
-- session ends. Nothing moves unless both sessions belong to one user and
-- the new one is live.
CREATE OR REPLACE FUNCTION auth_session_replace(p_old text, p_new text, p_reason text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $f$
BEGIN
    UPDATE oauth_refresh_tokens SET session_id = p_new
    WHERE session_id = p_old AND revoked_at IS NULL
      AND EXISTS (SELECT 1 FROM sessions o JOIN sessions n ON n.user_id = o.user_id
                  WHERE o.id = p_old AND n.id = p_new AND n.revoked_at IS NULL);
    UPDATE sessions SET revoked_at = now(), revoked_reason = p_reason WHERE id = p_old AND revoked_at IS NULL;
END
$f$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION auth_session_replace(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_session_replace(text, text, text) TO supermcp_app;

-- +goose Down
DROP FUNCTION IF EXISTS auth_session_replace(text, text, text);

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

DROP INDEX CONCURRENTLY IF EXISTS oauth_refresh_session_idx;
ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS amr;
ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS session_id;
ALTER TABLE oauth_codes DROP COLUMN IF EXISTS amr;
ALTER TABLE oauth_codes DROP COLUMN IF EXISTS session_id;
