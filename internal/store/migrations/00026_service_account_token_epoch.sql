-- +goose Up
-- +goose StatementBegin

-- Disabling a service account now refuses the access tokens it already
-- holds, not only new ones. An access token is a signed JWT nobody stores,
-- so it cannot be revoked row by row. Instead each account carries an
-- epoch that disabling it increments, a client_credentials token carries
-- the epoch it was issued under, and validation refuses a token whose
-- epoch is not the account's current one. Turning the account back on
-- leaves the epoch where it is, so the refused tokens stay refused.
--
-- A constant default adds the column without rewriting the table: the
-- ACCESS EXCLUSIVE lock is held for a catalogue change only.
--
-- Additive: an older replica during a rolling upgrade ignores the column,
-- issues tokens without the claim (read as epoch 0) and does not check it.
ALTER TABLE service_accounts ADD COLUMN IF NOT EXISTS token_epoch integer NOT NULL DEFAULT 0;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE service_accounts DROP COLUMN IF EXISTS token_epoch;
-- +goose StatementEnd
