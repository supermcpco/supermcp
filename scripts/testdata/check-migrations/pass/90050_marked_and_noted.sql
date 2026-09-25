-- supermcp:breaking (docs/UPGRADING.md says what this does to existing rows)
-- +goose Up
ALTER TABLE widgets ALTER COLUMN meta TYPE json USING meta::text::json;
