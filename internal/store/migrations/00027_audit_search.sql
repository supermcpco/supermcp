-- +goose NO TRANSACTION
-- +goose Up

-- Free-text search over the audit stream (GET /api/v1/audit?q=...,
-- internal/audit/read.go). Three pieces: audit_search_document, what an
-- event is searched by; audit_events_search_idx, a GIN index over it; and
-- audit_search, the function the list calls to find one workspace's
-- matching events through that index.
--
-- An expression index rather than a generated column. Adding a stored
-- generated column rewrites audit_events under an ACCESS EXCLUSIVE lock,
-- which stops every append (and every request that records one) for as
-- long as the rewrite takes on a large trail. An expression index needs no
-- column and builds CONCURRENTLY. Nothing is added to the row either, so
-- nothing changes for the hash chain: the chain covers named columns and
-- the digest of diff, payload and meta (audit.ContentHash), `audit verify`
-- reads named columns, and retention, scrubbing and legal hold update and
-- delete rows the way they did.
--
-- What is searched: the action, who acted (id and display name, which is
-- where an email is kept), what was acted on (kind, id and display name),
-- and the string values of meta. Not diff or payload, which can hold what a
-- tool was given and returned and are governed by the payload policy; not
-- the IP, user agent, request or session ids.
--
-- One thing in meta comes from outside and is kept whatever the payload
-- policy: a failed tool call's error (meta.error). It is redacted before it
-- is recorded (internal/invoke errorText: a credential in a URL or DSN, and
-- what the masked policy would remove), but a plain word the caller sent
-- that the upstream quoted back can still be in it, and so be found.
--
-- The 'simple' configuration: no stemming and no stop words. The stream is
-- mostly identifiers, action names and slugs, which english would stem
-- ("created" becomes "creat") or drop ("a", "on"), and a query goes
-- through the same configuration, so what is typed is what is matched.
--
-- Each text is indexed twice: as written, and with . @ / : turned into
-- spaces. The parser keeps "connector.created" and "alice@example.com"
-- whole, so the first lets the whole name match and the second lets
-- "connector" or "alice" match on their own.
--
-- The document must never raise: an index expression that raises refuses
-- the insert, and that would refuse the audit event. meta is json, and
-- reading its strings means turning it into jsonb, which raises on two
-- things:
--
--   * An escaped NUL (\u0000), which Go writes for a NUL in a string. It is
--     replaced with an escaped space before the cast, so the rest of the
--     string, and the rest of meta, is still searched.
--   * In a database whose encoding is not UTF8, an escape above \u007f,
--     which Go writes for U+2028 and U+2029. There a meta holding one is
--     not searched; its event is still found by its other columns.
--
-- And a tsvector holds at most 1 MB of lexemes and refuses more, so the
-- text is cut at 100,000 characters (it is indexed twice). meta is not
-- size-capped the way payload is, so the columns go first, then the meta
-- keys searched most (target, server, connector, tool, reason), then the
-- rest of meta: a long list elsewhere in meta cannot push those past the
-- cut.
--
-- IMMUTABLE is true of everything here but getdatabaseencoding(), which is
-- fixed when the database is created.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_search_document(
    action text, actor_id text, actor_display text,
    target_kind text, target_id text, target_display text, meta json)
RETURNS tsvector
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $f$
    SELECT pg_catalog.to_tsvector('pg_catalog.simple'::pg_catalog.regconfig, d)
        || pg_catalog.to_tsvector('pg_catalog.simple'::pg_catalog.regconfig, pg_catalog.translate(d, '.@/:', '    '))
    FROM (
        SELECT pg_catalog.left(
            COALESCE($1, '') || ' ' || COALESCE($2, '') || ' ' || COALESCE($3, '') || ' '
            || COALESCE($4, '') || ' ' || COALESCE($5, '') || ' ' || COALESCE($6, '') || ' '
            || COALESCE(pg_catalog.jsonb_path_query_array(j -> 'target', 'strict $.** ? (@.type() == "string")')::text, '') || ' '
            || COALESCE(pg_catalog.jsonb_path_query_array(j -> 'server', 'strict $.** ? (@.type() == "string")')::text, '') || ' '
            || COALESCE(pg_catalog.jsonb_path_query_array(j -> 'connector', 'strict $.** ? (@.type() == "string")')::text, '') || ' '
            || COALESCE(pg_catalog.jsonb_path_query_array(j -> 'tool', 'strict $.** ? (@.type() == "string")')::text, '') || ' '
            || COALESCE(pg_catalog.jsonb_path_query_array(j -> 'reason', 'strict $.** ? (@.type() == "string")')::text, '') || ' '
            || COALESCE(pg_catalog.jsonb_path_query_array(
                   CASE WHEN pg_catalog.jsonb_typeof(j) = 'object'
                        THEN j OPERATOR(pg_catalog.-) ARRAY['target', 'server', 'connector', 'tool', 'reason']
                        ELSE j END,
                   'strict $.** ? (@.type() == "string")')::text, ''),
            100000) AS d
        FROM (
            SELECT CASE
                WHEN $7 IS NULL THEN NULL
                WHEN pg_catalog.getdatabaseencoding() <> 'UTF8'
                     AND $7::text ~ E'\\\\u(?!00[0-7])' THEN NULL
                ELSE pg_catalog.replace($7::text, E'\\u0000', E'\\u0020')::jsonb
            END AS j
        ) m
    ) s
$f$;
-- +goose StatementEnd

-- audit_search returns the sequence numbers of the calling workspace's
-- events that match a search and the list's other filters, newest first,
-- one page of them. The list reads the events themselves by those numbers.
--
-- Why a function, and why SECURITY DEFINER: audit_events has row-level
-- security, forced, and a query the application role runs has the policy
-- applied before any of its own conditions that are not leakproof. The
-- text-search match (@@) is not leakproof, so under the policy Postgres
-- cannot use the index for it: it reads every one of the workspace's
-- events and builds each one's document to test it, which on a large
-- workspace takes minutes. This function runs as its owner, the role that
-- ran the migrations, which has BYPASSRLS, so the planner may use the
-- index. It restricts to the workspace itself, and takes the workspace
-- from the same setting the policy reads (current_org()), not from its
-- caller, so it can answer for no other workspace than the one the
-- policy would have allowed. With no workspace set it returns nothing.
--
-- The statement is run with EXECUTE so it is planned for the values it is
-- given: whether the index or a walk back from the newest event is faster
-- depends on how common the words are, which a plan made for any words
-- cannot know.
--
-- Only the application role may call it.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_search(
    p_q text, p_category text, p_action text, p_actor_id text, p_target_id text, p_outcome text,
    p_from timestamptz, p_to timestamptz, p_after_seq bigint, p_limit integer)
RETURNS SETOF bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $f$
DECLARE
    org text := public.current_org();
BEGIN
    IF org IS NULL OR p_q IS NULL OR pg_catalog.btrim(p_q) = '' THEN
        RETURN;
    END IF;
    RETURN QUERY EXECUTE $q$
        SELECT seq FROM public.audit_events
        WHERE organization_id = $1
          AND public.audit_search_document(action, actor_id, actor_display, target_kind, target_id, target_display, meta)
              @@ pg_catalog.websearch_to_tsquery('pg_catalog.simple'::pg_catalog.regconfig, $2)
          AND ($3 = '' OR category = $3)
          AND ($4 = '' OR action = $4)
          AND ($5 = '' OR actor_id = $5)
          AND ($6 = '' OR target_id = $6)
          AND ($7 = '' OR outcome = $7)
          AND ($8::timestamptz IS NULL OR ts >= $8)
          AND ($9::timestamptz IS NULL OR ts <= $9)
          AND ($10 = 0 OR seq < $10)
        ORDER BY seq DESC
        LIMIT $11
    $q$
    USING org, p_q, COALESCE(p_category, ''), COALESCE(p_action, ''), COALESCE(p_actor_id, ''),
          COALESCE(p_target_id, ''), COALESCE(p_outcome, ''), p_from, p_to, COALESCE(p_after_seq, 0),
          LEAST(GREATEST(COALESCE(p_limit, 100), 1), 500);
END
$f$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION audit_search(text, text, text, text, text, text, timestamptz, timestamptz, bigint, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_search(text, text, text, text, text, text, timestamptz, timestamptz, bigint, integer) TO supermcp_app;

-- CONCURRENTLY so the build does not block writes to audit_events, which
-- every request appends to. That cannot run inside a transaction, hence
-- NO TRANSACTION above.
--
-- A concurrent build that fails (cancelled, timed out, a lost connection)
-- leaves an invalid index behind under the same name, and goose does not
-- record the migration as applied. The DROP first makes a rerun rebuild it
-- instead of seeing the name and skipping, which is what IF NOT EXISTS
-- alone would do. On a clean database it drops nothing.
DROP INDEX CONCURRENTLY IF EXISTS audit_events_search_idx;
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_search_idx ON audit_events
    USING gin (audit_search_document(action, actor_id, actor_display, target_kind, target_id, target_display, meta));

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS audit_events_search_idx;
DROP FUNCTION IF EXISTS audit_search(text, text, text, text, text, text, timestamptz, timestamptz, bigint, integer);
DROP FUNCTION IF EXISTS audit_search_document(text, text, text, text, text, text, json);
