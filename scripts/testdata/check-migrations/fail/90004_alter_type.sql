-- expect: 7: ALTER COLUMN meta TYPE on widgets
-- expect: 8: ALTER COLUMN size SET NOT NULL on widgets
-- expect: 9: ALTER COLUMN name TYPE on widgets
-- +goose Up
-- +goose StatementBegin
ALTER TABLE widgets
    ALTER COLUMN meta TYPE json USING meta::text::json,
    ALTER size SET NOT NULL,
    ALTER COLUMN name SET DATA TYPE varchar(40);
-- +goose StatementEnd
