-- expect: 6: DROP COLUMN colour on widgets
-- expect: 7: DROP COLUMN size on widgets
-- expect: 8: DROP CONSTRAINT widgets_size_check on widgets
-- +goose Up
ALTER TABLE widgets
    DROP COLUMN IF EXISTS colour,
    DROP size,
    DROP CONSTRAINT widgets_size_check;
-- +goose Down
