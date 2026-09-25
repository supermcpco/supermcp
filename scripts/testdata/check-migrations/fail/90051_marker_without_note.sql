-- expect: 5: ALTER COLUMN meta TYPE on widgets
-- expect-note: does not mention 90051
-- supermcp:breaking
-- +goose Up
ALTER TABLE widgets ALTER COLUMN meta TYPE json;
