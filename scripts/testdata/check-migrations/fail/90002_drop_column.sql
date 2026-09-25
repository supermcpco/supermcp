-- expect: 5: DROP COLUMN colour on widgets
-- expect: 6: DROP COLUMN size on widgets
-- +goose Up
ALTER TABLE widgets
    DROP COLUMN IF EXISTS colour,
    DROP size,
    DROP CONSTRAINT widgets_size_check;
-- +goose Down
