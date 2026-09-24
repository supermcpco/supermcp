-- +goose Up
-- +goose StatementBegin

-- An identity provider issues an answer to whoever asks for one. Without
-- binding the sign-in to the browser that started it, somebody signs in
-- as themselves, delivers the answer to another person's browser, and
-- that person is signed in as them: every credential they connect after
-- that lands in the attacker's workspace. The state parameter alone does
-- not stop it, because the attacker holds a state of their own.
--
-- The column carries the digest of a cookie set when the sign-in starts.
-- A digest rather than the value, so a reader of the table cannot forge
-- the cookie and finish somebody else's sign-in. It is nullable and
-- defaults to empty so that a request already in flight when this is
-- applied still completes; new ones always carry it.
ALTER TABLE sso_requests ADD COLUMN IF NOT EXISTS binding text NOT NULL DEFAULT '';

-- The return type changes, so the old definitions go first: Postgres
-- refuses to replace a function whose signature it cannot keep.
DROP FUNCTION IF EXISTS auth_sso_request_create(text, text, text, text, text, timestamptz);
DROP FUNCTION IF EXISTS auth_sso_request_consume(text);

CREATE OR REPLACE FUNCTION auth_sso_request_create(p_state text, p_idp text, p_nonce text, p_verifier text,
                                                   p_redirect text, p_expires timestamptz, p_binding text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    INSERT INTO sso_requests (state, idp_id, nonce, code_verifier, redirect_after, expires_at, binding)
    VALUES (p_state, p_idp, p_nonce, p_verifier, p_redirect, p_expires, p_binding)
$f$;

CREATE OR REPLACE FUNCTION auth_sso_request_consume(p_state text)
RETURNS TABLE (state text, idp_id text, nonce text, code_verifier text, redirect_after text,
               expires_at timestamptz, binding text)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    UPDATE sso_requests SET consumed_at = now()
    WHERE sso_requests.state = p_state AND consumed_at IS NULL
    RETURNING sso_requests.state, sso_requests.idp_id, sso_requests.nonce, sso_requests.code_verifier,
              sso_requests.redirect_after, sso_requests.expires_at, sso_requests.binding
$f$;

REVOKE EXECUTE ON FUNCTION
    auth_sso_request_create(text, text, text, text, text, timestamptz, text),
    auth_sso_request_consume(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    auth_sso_request_create(text, text, text, text, text, timestamptz, text),
    auth_sso_request_consume(text) TO supermcp_app;

-- A role is a versioned entity like a connector: the same history screen,
-- the same restore. The constraint listed the kinds that existed when it
-- was written.
ALTER TABLE revisions DROP CONSTRAINT IF EXISTS revisions_entity_kind_check;
ALTER TABLE revisions ADD CONSTRAINT revisions_entity_kind_check
    CHECK (entity_kind IN ('connector', 'tool', 'server', 'role'));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE revisions DROP CONSTRAINT IF EXISTS revisions_entity_kind_check;
DELETE FROM revisions WHERE entity_kind = 'role';
ALTER TABLE revisions ADD CONSTRAINT revisions_entity_kind_check
    CHECK (entity_kind IN ('connector', 'tool', 'server'));
ALTER TABLE sso_requests DROP COLUMN IF EXISTS binding;
-- +goose StatementEnd
