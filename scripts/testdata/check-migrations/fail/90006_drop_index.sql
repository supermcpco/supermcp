-- expect: 5: DROP INDEX widgets_colour_idx
-- +goose NO TRANSACTION
-- +goose Up
CREATE INDEX CONCURRENTLY IF NOT EXISTS widgets_size_idx ON widgets (size);
DROP INDEX CONCURRENTLY IF EXISTS widgets_size_idx, public.widgets_colour_idx;
