-- expect: 4: DROP TABLE widgets
-- expect-note: add the line '-- supermcp:breaking' in the migration.
-- +goose Up
DROP TABLE widgets;
