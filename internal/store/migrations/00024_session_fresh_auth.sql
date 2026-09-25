-- +goose NO TRANSACTION
-- +goose Up

-- A session remembers when its holder last proved who they are, so that
-- the operations that hand out credentials or change who may do what can
-- ask for a recent proof rather than trusting a cookie that may be weeks
-- old. authenticated_at is set when a session is created: now() for a
-- password, and for single sign-on the time the provider says the person
-- authenticated, or '-infinity' when it does not say. It is moved again by
-- a password re-authentication. last_seen_at, which every request moves,
-- says nothing about it. auth_provider_id names the single sign-on
-- provider a session came from, so the interface can send its holder back
-- through the same one.
--
-- Expand only. An older replica still running during the roll inserts
-- sessions without naming the new columns, and the default fills
-- authenticated_at; it reads sessions through auth_session and starts
-- sign-ins through the functions of 00013 and 00017, all left as they were.
--
-- NO TRANSACTION so that no statement here holds a lock for long: every
-- request reads the sessions table. Each statement is safe to run again
-- if the migration is interrupted.
--
-- The column is added with a constant default, which is a catalogue
-- change only: existing rows read '-infinity' without being rewritten.
-- The default then becomes now() for rows inserted from here on.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS authenticated_at timestamptz NOT NULL DEFAULT '-infinity';
ALTER TABLE sessions ALTER COLUMN authenticated_at SET DEFAULT now();
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS auth_provider_id text;

-- The session a re-authentication through a provider replaces travels on
-- the sign-in's own request row, so it is tied to that sign-in and to
-- nothing else. Nullable: an ordinary sign-in replaces nothing.
ALTER TABLE sso_requests ADD COLUMN IF NOT EXISTS replaces_session text;
ALTER TABLE saml_requests ADD COLUMN IF NOT EXISTS replaces_session text;

-- A live session that existed before this migration proved its holder
-- when it was created and not since. Revoked and expired rows keep
-- '-infinity': nothing reads them. Batches of 1000 by id, each committed
-- on its own, so a request touching a session waits for one batch at
-- most, never for the whole table.
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
        UPDATE sessions SET authenticated_at = created_at
        WHERE id > after AND id <= upto
          AND revoked_at IS NULL AND absolute_expires_at > now()
          AND authenticated_at = '-infinity';
        after := upto;
        COMMIT;
    END LOOP;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Pre-tenant reads and writes, as in 00002: a session is loaded before
-- anyone knows which organisation the request is for. '-infinity' comes
-- back as NULL: a time nobody vouched for.
CREATE OR REPLACE FUNCTION auth_session_load(p_id text)
RETURNS TABLE (id text, user_id text, organization_id text, idle_expires_at timestamptz, absolute_expires_at timestamptz,
               mfa_verified_at timestamptz, auth_method text, revoked_at timestamptz, last_seen_at timestamptz,
               authenticated_at timestamptz, auth_provider_id text)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT s.id, s.user_id, s.organization_id, s.idle_expires_at, s.absolute_expires_at,
           s.mfa_verified_at, s.auth_method, s.revoked_at, s.last_seen_at,
           NULLIF(s.authenticated_at, '-infinity'::timestamptz), s.auth_provider_id
    FROM sessions s WHERE s.id = p_id
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
-- p_at NULL records a sign-in whose time nobody vouched for.
CREATE OR REPLACE FUNCTION auth_session_open(p_id text, p_user_id text, p_org text, p_idle timestamptz, p_abs timestamptz,
                                             p_method text, p_provider text, p_at timestamptz, p_ip inet, p_ua text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    INSERT INTO sessions (id, user_id, organization_id, idle_expires_at, absolute_expires_at, auth_method,
                          auth_provider_id, authenticated_at, ip, user_agent)
    VALUES (p_id, p_user_id, p_org, p_idle, p_abs, p_method, p_provider,
            COALESCE(p_at, '-infinity'::timestamptz), p_ip, p_ua)
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
-- A password re-authentication moves the clock on the session the person
-- is using. The user id is part of the match so a session id alone cannot
-- be used to refresh somebody else's session. Returns NULL when the
-- session is gone or revoked.
CREATE OR REPLACE FUNCTION auth_session_reauth(p_id text, p_user text)
RETURNS timestamptz LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    UPDATE sessions SET authenticated_at = now()
    WHERE id = p_id AND user_id = p_user AND revoked_at IS NULL
    RETURNING authenticated_at
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth_sso_request_open(p_state text, p_idp text, p_nonce text, p_verifier text,
                                                 p_redirect text, p_expires timestamptz, p_binding text, p_replaces text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    INSERT INTO sso_requests (state, idp_id, nonce, code_verifier, redirect_after, expires_at, binding, replaces_session)
    VALUES (p_state, p_idp, p_nonce, p_verifier, p_redirect, p_expires, p_binding, p_replaces)
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Consumes the request and returns it, as auth_sso_request_consume does,
-- with the session it replaces.
CREATE OR REPLACE FUNCTION auth_sso_request_take(p_state text)
RETURNS TABLE (state text, idp_id text, nonce text, code_verifier text, redirect_after text,
               expires_at timestamptz, binding text, replaces_session text)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    UPDATE sso_requests SET consumed_at = now()
    WHERE sso_requests.state = p_state AND consumed_at IS NULL
    RETURNING sso_requests.state, sso_requests.idp_id, sso_requests.nonce, sso_requests.code_verifier,
              sso_requests.redirect_after, sso_requests.expires_at, sso_requests.binding,
              sso_requests.replaces_session
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth_saml_request_open(p_id text, p_provider text, p_redirect text,
                                                  p_expires timestamptz, p_binding text, p_replaces text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    INSERT INTO saml_requests (id, provider_id, redirect_after, expires_at, binding, replaces_session)
    VALUES (p_id, p_provider, p_redirect, p_expires, p_binding, p_replaces)
$f$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth_saml_request_load(p_id text, p_provider text)
RETURNS TABLE (id text, redirect_after text, expires_at timestamptz, binding text, replaces_session text)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $f$
    SELECT r.id, r.redirect_after, r.expires_at, r.binding, r.replaces_session
    FROM saml_requests r WHERE r.id = p_id AND r.provider_id = p_provider
$f$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION auth_session_load(text),
    auth_session_open(text, text, text, timestamptz, timestamptz, text, text, timestamptz, inet, text),
    auth_session_reauth(text, text),
    auth_sso_request_open(text, text, text, text, text, timestamptz, text, text),
    auth_sso_request_take(text),
    auth_saml_request_open(text, text, text, timestamptz, text, text),
    auth_saml_request_load(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_session_load(text),
    auth_session_open(text, text, text, timestamptz, timestamptz, text, text, timestamptz, inet, text),
    auth_session_reauth(text, text),
    auth_sso_request_open(text, text, text, text, text, timestamptz, text, text),
    auth_sso_request_take(text),
    auth_saml_request_open(text, text, text, timestamptz, text, text),
    auth_saml_request_load(text, text) TO supermcp_app;

-- +goose Down
DROP FUNCTION IF EXISTS auth_saml_request_load(text, text),
    auth_saml_request_open(text, text, text, timestamptz, text, text),
    auth_sso_request_take(text),
    auth_sso_request_open(text, text, text, text, text, timestamptz, text, text),
    auth_session_reauth(text, text),
    auth_session_open(text, text, text, timestamptz, timestamptz, text, text, timestamptz, inet, text),
    auth_session_load(text);
ALTER TABLE saml_requests DROP COLUMN IF EXISTS replaces_session;
ALTER TABLE sso_requests DROP COLUMN IF EXISTS replaces_session;
ALTER TABLE sessions DROP COLUMN IF EXISTS auth_provider_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS authenticated_at;
