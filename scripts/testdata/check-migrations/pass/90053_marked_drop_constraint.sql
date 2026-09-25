-- supermcp:breaking (docs/UPGRADING.md says what replaces the unique name)
-- +goose Up
ALTER TABLE widgets DROP CONSTRAINT widgets_name_key;
-- +goose Down
ALTER TABLE widgets ADD CONSTRAINT widgets_name_key UNIQUE (name);
