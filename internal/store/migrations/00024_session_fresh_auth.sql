-- +goose NO TRANSACTION
-- +goose Up

-- A session remembers when its holder last proved who they are, so that
-- the operations that hand out credentials or change who may do what can
-- ask for a recent proof rather than trusting a cookie that may be weeks
-- old. authenticated_at is set when a session is created and again when
-- its holder re-authenticates; last_seen_at, which every request moves,
-- says nothing about that. auth_provider_id names the single sign-on
-- provider a session came from, so the interface can send its holder back
-- through the same one.
--
-- Expand only. An older replica still running during the roll inserts
-- sessions without naming the new columns, and the default fills
-- authenticated_at; it reads sessions through auth_session, which is left
-- as it was.
--
-- NO TRANSACTION so that the backfill does not run under the ACCESS
-- EXCLUSIVE lock the ALTER takes: every request reads this table. The
-- ALTER is a catalogue change only (a default that is not volatile is
-- stored, not written into every row), the UPDATE takes row locks, and
-- each statement is safe to run again if the migration is interrupted.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS authenticated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS auth_provider_id text;

-- A session that existed before this migration proved its holder when it
-- was created and not since.
UPDATE sessions SET authenticated_at = created_at WHERE authenticated_at <> created_at;

-- +goose StatementBegin
-- Pre-tenant reads and writes, as in 00002: a session is loaded before
-- anyone knows which organisation the request is for.
CREATE OR REPLACE FUNCTION auth_session_load(p_id text)
RETURNS TABLE (id text, user_id text, organization_id text, idle_expires_at timestamptz, absolute_expires_at timestamptz,
               mfa_verified_at timestamptz, auth_method text, revoked_at timestamptz, last_seen_at timestamptz,
               authenticated_at timestamptz, auth_provider_id text)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT s.id, s.user_id, s.organization_id, s.idle_expires_at, s.absolute_expires_at,
           s.mfa_verified_at, s.auth_method, s.revoked_at, s.last_seen_at,
           s.authenticated_at, s.auth_provider_id
    FROM sessions s WHERE s.id = p_id
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth_session_open(p_id text, p_user_id text, p_org text, p_idle timestamptz, p_abs timestamptz,
                                             p_method text, p_provider text, p_ip inet, p_ua text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    INSERT INTO sessions (id, user_id, organization_id, idle_expires_at, absolute_expires_at, auth_method,
                          auth_provider_id, ip, user_agent)
    VALUES (p_id, p_user_id, p_org, p_idle, p_abs, p_method, p_provider, p_ip, p_ua)
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Re-authentication moves the clock on the session the person is using.
-- The user id is part of the match so a session id alone cannot be used
-- to refresh somebody else's session. Returns nothing when the session is
-- gone or revoked.
CREATE OR REPLACE FUNCTION auth_session_reauth(p_id text, p_user text)
RETURNS timestamptz LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    UPDATE sessions SET authenticated_at = now()
    WHERE id = p_id AND user_id = p_user AND revoked_at IS NULL
    RETURNING authenticated_at
$f$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION auth_session_load(text),
    auth_session_open(text, text, text, timestamptz, timestamptz, text, text, inet, text),
    auth_session_reauth(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_session_load(text),
    auth_session_open(text, text, text, timestamptz, timestamptz, text, text, inet, text),
    auth_session_reauth(text, text) TO supermcp_app;

-- +goose Down
DROP FUNCTION IF EXISTS auth_session_reauth(text, text),
    auth_session_open(text, text, text, timestamptz, timestamptz, text, text, inet, text),
    auth_session_load(text);
ALTER TABLE sessions DROP COLUMN IF EXISTS auth_provider_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS authenticated_at;
