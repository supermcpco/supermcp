-- +goose Up
-- Baseline. Domain tables arrive in later migrations; this one records the
-- instance identity and proves the migration path end to end.
CREATE TABLE instance (
    id          text PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO instance (id) VALUES (gen_random_uuid()::text) ON CONFLICT DO NOTHING;

-- +goose Down
DROP TABLE instance;
