-- expect: 8: DELETE FROM widgets
-- expect: 9: DROP TABLE gadgets
-- +goose Up
-- +goose StatementBegin
DO $body$
BEGIN
    RAISE NOTICE 'this; is not the end';
    DELETE FROM widgets;
    DROP TABLE gadgets;
END
$body$;
-- +goose StatementEnd
