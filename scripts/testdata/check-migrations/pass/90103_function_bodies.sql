-- +goose Up
-- +goose StatementBegin
-- Runs when called, not when the migration applies.
CREATE OR REPLACE FUNCTION widgets_sweep() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER AS $fn$
BEGIN
    DELETE FROM widgets WHERE expires_at < now() - interval '1 hour';
    EXECUTE format($q$SELECT %L$q$, 'x');
END
$fn$;
CREATE FUNCTION widgets_purge() RETURNS void LANGUAGE sql AS $$
    TRUNCATE widgets_scratch;
$$;
-- +goose StatementEnd
