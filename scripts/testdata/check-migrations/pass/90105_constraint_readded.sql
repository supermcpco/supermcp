-- The pattern 00014, 00017 and 00028 use: widen a CHECK by dropping it and
-- adding it back under the same name, in the same statement or the next
-- one, quoted or not, with or without the schema. A constraint this
-- migration added itself may also be dropped again.
-- +goose Up
-- +goose StatementBegin
ALTER TABLE widgets DROP CONSTRAINT IF EXISTS widgets_kind_check;
ALTER TABLE public.widgets ADD CONSTRAINT "widgets_kind_check"
    CHECK (kind IN ('a', 'b', 'c'));

ALTER TABLE ONLY gadgets
    DROP CONSTRAINT gadgets_size_check,
    ADD CONSTRAINT gadgets_size_check CHECK (size >= 0);

ALTER TABLE gadgets ADD CONSTRAINT gadgets_tmp_check CHECK (true) NOT VALID;
ALTER TABLE gadgets DROP CONSTRAINT gadgets_tmp_check;
-- +goose StatementEnd
-- +goose Down
ALTER TABLE widgets DROP CONSTRAINT IF EXISTS widgets_kind_check;
