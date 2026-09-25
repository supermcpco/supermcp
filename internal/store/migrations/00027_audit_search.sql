-- +goose NO TRANSACTION
-- +goose Up

-- Free-text search over the audit stream (GET /api/v1/audit?q=...,
-- internal/audit/read.go). What is searched is the one function below, and
-- the list query calls it with the same arguments, which is what lets the
-- planner use the index: change one and the other has to change with it.
-- internal/audit/search_db_test.go checks the plan.
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
-- meta is json, and turning it into jsonb, or reading its strings in any
-- other way, raises on an escaped NUL (\u0000), which Go writes for a NUL
-- in a string. An index expression that raises refuses the insert, and
-- that would refuse the audit event. So a meta whose text holds the escape
-- anywhere is not searched; its row is still found by its other columns.
-- For the same reason the text is cut at 100,000 characters: a tsvector
-- holds at most 1 MB of lexemes and refuses more, and the text is indexed
-- twice. meta is not size-capped the way payload is, but nothing the
-- gateway records comes near that.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_search_document(
    action text, actor_id text, actor_display text,
    target_kind text, target_id text, target_display text, meta json)
RETURNS tsvector
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $f$
    SELECT pg_catalog.to_tsvector('pg_catalog.simple'::pg_catalog.regconfig, d)
        || pg_catalog.to_tsvector('pg_catalog.simple'::pg_catalog.regconfig, pg_catalog.translate(d, '.@/:', '    '))
    FROM (SELECT pg_catalog.left(
              COALESCE($1, '') || ' ' || COALESCE($2, '') || ' ' || COALESCE($3, '') || ' '
              || COALESCE($4, '') || ' ' || COALESCE($5, '') || ' ' || COALESCE($6, '') || ' '
              || CASE WHEN $7 IS NULL OR pg_catalog.strpos($7::text, '\u0000') > 0 THEN ''
                      ELSE pg_catalog.jsonb_path_query_array($7::jsonb,
                               'strict $.** ? (@.type() == "string")')::text
                 END, 100000) AS d) s
$f$;
-- +goose StatementEnd

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
DROP FUNCTION IF EXISTS audit_search_document(text, text, text, text, text, text, json);
