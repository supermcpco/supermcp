-- expect: 5: DROP CONSTRAINT widgets_kind_check on widgets
-- A new name is a new constraint: the old one is gone, and nothing says the
-- new one is the superset the previous release needs.
-- +goose Up
ALTER TABLE widgets DROP CONSTRAINT IF EXISTS widgets_kind_check;
ALTER TABLE widgets ADD CONSTRAINT widgets_kind_check_v2
    CHECK (kind IN ('a', 'b', 'c'));
-- +goose Down
ALTER TABLE widgets DROP CONSTRAINT IF EXISTS widgets_kind_check_v2;
