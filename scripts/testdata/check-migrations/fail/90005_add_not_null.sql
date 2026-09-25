-- expect: 5: ADD COLUMN owner NOT NULL without DEFAULT on widgets
-- expect: 6: ADD COLUMN serial NOT NULL without DEFAULT on widgets
-- +goose Up
-- A CHECK constraint that mentions NOT NULL is not a column and is fine.
ALTER TABLE widgets ADD COLUMN IF NOT EXISTS owner text NOT NULL CHECK (owner IS NOT NULL);
ALTER TABLE widgets ADD serial bigint PRIMARY KEY, ADD CONSTRAINT c CHECK (serial IS NOT NULL);
