-- +goose Up
-- +goose StatementBegin
CREATE TABLE widgets (
    id     text PRIMARY KEY,
    colour text NOT NULL DEFAULT '',
    owner  text NOT NULL,
    CHECK (colour IS NOT NULL)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM widgets;
ALTER TABLE widgets DROP COLUMN colour, ALTER COLUMN owner TYPE varchar(10);
DROP TABLE IF EXISTS widgets;
-- +goose StatementEnd
