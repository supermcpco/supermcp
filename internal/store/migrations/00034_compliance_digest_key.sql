-- +goose Up
-- The compliance reports replace each secret with a digest so that two
-- runs can be compared without either run holding the secret. A plain
-- hash of a password can be looked up offline from a word list, so the
-- digest is keyed with a secret that only this instance holds. Two
-- gen_random_uuid() calls give 256 bits from the server's strong
-- generator without needing pgcrypto.
INSERT INTO site_settings (key, value)
VALUES ('compliance.digest_key', to_jsonb(replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '')))
ON CONFLICT (key) DO NOTHING;

-- +goose Down
DELETE FROM site_settings WHERE key = 'compliance.digest_key';
