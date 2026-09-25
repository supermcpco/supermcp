-- expect: 9: DROP CONSTRAINT gadgets_widget_id_fkey on gadgets
-- expect: 15: DROP CONSTRAINT gadgets_owner_fkey on gadgets
-- +goose Up
-- +goose StatementBegin
-- A comment saying ADD CONSTRAINT gadgets_widget_id_fkey does not add it,
-- nor does a string, nor the same name on another table.
DO $$
BEGIN
    ALTER TABLE gadgets DROP CONSTRAINT gadgets_widget_id_fkey;
    RAISE NOTICE 'ALTER TABLE gadgets ADD CONSTRAINT gadgets_widget_id_fkey';
    ALTER TABLE sprockets ADD CONSTRAINT gadgets_widget_id_fkey CHECK (true);
    ALTER TABLE gadgets DROP CONSTRAINT gadgets_owner_fkey;
    ALTER TABLE gadgets ADD CONSTRAINT gadgets_owner_fkey
        FOREIGN KEY (owner_id) REFERENCES owners (id) NOT VALID;
    ALTER TABLE gadgets DROP CONSTRAINT gadgets_owner_fkey;
END
$$;
-- +goose StatementEnd
