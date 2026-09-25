-- expect: 10: DROP CONSTRAINT widgets_name_key on widgets
-- The previous release relies on the unique name to find a widget; without
-- the constraint it can write a second row with the same name. The Down
-- section adding it back does not help a rolling upgrade.
-- +goose Up
-- +goose StatementBegin
ALTER TABLE widgets ADD COLUMN IF NOT EXISTS slug text;

ALTER TABLE IF EXISTS ONLY public.widgets
    DROP CONSTRAINT IF EXISTS
        "WIDGETS_NAME_KEY"
    CASCADE;
-- +goose StatementEnd
-- +goose Down
ALTER TABLE widgets ADD CONSTRAINT widgets_name_key UNIQUE (name);
