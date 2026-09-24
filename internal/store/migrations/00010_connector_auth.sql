-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- Connector consent requests
--
-- One row per authorization code flow in flight: an administrator has been
-- sent to a vendor's consent screen, and this is what the callback will
-- need when the browser comes back with a code.
--
-- A table rather than a cookie, for the same reason sso_requests is one in
-- 00005. The state has to be good exactly once, and single use is a
-- property of a record the server consumes: a cookie is a copy the browser
-- holds, and a replay of it looks identical to the first use. The round
-- trip also goes through the vendor's site, so the cookie would have to be
-- sent on a cross-site navigation back to us — and anything that can set a
-- cookie for this instance could then choose the state and the verifier
-- the callback checks against, which is precisely what state and PKCE are
-- there to prevent.
--
-- No organization_id: the connector has one, and a second copy here could
-- only ever disagree with it. The consuming function reads the owner from
-- the connector, so the callback acts for whoever owns it now.
--
-- The code verifier is stored in clear. It is a nonce for one exchange,
-- minutes long, useless without the vendor's code, and sealing it would
-- put a key operation between the callback and a row it has to read
-- without a tenant.
CREATE TABLE connector_auth_requests (
    state          text PRIMARY KEY,
    connector_id   text NOT NULL REFERENCES connectors ON DELETE CASCADE,
    code_verifier  text NOT NULL,
    actor_id       text,                     -- who asked for the consent
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz
);
CREATE INDEX connector_auth_requests_expiry_idx ON connector_auth_requests (expires_at);

-- Row-level security with no policy, as sso_requests has: a consent has no
-- tenant of its own to be matched against, and nothing reads this table
-- except the two functions below. Fail closed, and let the definer decide.
ALTER TABLE connector_auth_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_auth_requests FORCE ROW LEVEL SECURITY;

GRANT SELECT ON connector_auth_requests TO supermcp_app;

CREATE OR REPLACE FUNCTION connector_auth_request_create(p_state text, p_connector text,
                                                        p_verifier text, p_actor text, p_expires timestamptz)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    -- There is no sweep for this table and a spent request is worth
    -- nothing, so each new one takes the rubbish out behind it.
    DELETE FROM connector_auth_requests WHERE expires_at < now() - interval '1 hour';
    INSERT INTO connector_auth_requests (state, connector_id, code_verifier, actor_id, expires_at)
    VALUES (p_state, p_connector, p_verifier, NULLIF(p_actor, ''), p_expires);
$f$;

-- Consumes the request and returns it, with the organisation that owns the
-- connector. A state is good once, so the read and the write have to be
-- the same statement; a second call for the same value returns no row,
-- which the caller reads as a replay.
CREATE OR REPLACE FUNCTION connector_auth_request_consume(p_state text)
RETURNS TABLE (state text, connector_id text, organization_id text, code_verifier text,
               actor_id text, expires_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $f$
    WITH spent AS (
        UPDATE connector_auth_requests r SET consumed_at = now()
        WHERE r.state = p_state AND r.consumed_at IS NULL
        RETURNING r.state, r.connector_id, r.code_verifier, COALESCE(r.actor_id, '') AS actor_id, r.expires_at
    )
    SELECT s.state, s.connector_id, c.organization_id, s.code_verifier, s.actor_id, s.expires_at
    FROM spent s JOIN connectors c ON c.id = s.connector_id;
$f$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS connector_auth_request_consume(text),
    connector_auth_request_create(text, text, text, text, timestamptz);
DROP TABLE IF EXISTS connector_auth_requests;
-- +goose StatementEnd
