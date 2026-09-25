-- expect: 5: ALTER TABLE widgets RENAME
-- expect: 6: ALTER TABLE gadgets RENAME
-- expect: 7: ALTER INDEX ... RENAME
-- +goose Up
ALTER TABLE widgets RENAME COLUMN colour TO color;
ALTER TABLE IF EXISTS public.gadgets RENAME TO things;
ALTER INDEX widgets_idx RENAME TO widgets_colour_idx;
