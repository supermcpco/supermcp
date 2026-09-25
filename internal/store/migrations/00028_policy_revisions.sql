-- +goose Up
-- +goose StatementBegin

-- The rules that decide what a tool call may carry, which calls need a
-- person and who may sign in are versioned like a connector: the same
-- history screen, the same restore. OIDC and SAML providers live in two
-- tables with two id spaces, so they are two kinds. The constraint listed
-- the kinds that existed when it was written; the new list is a superset,
-- so a replica of the previous release, which writes only the old kinds,
-- is unaffected.
ALTER TABLE revisions DROP CONSTRAINT IF EXISTS revisions_entity_kind_check;
ALTER TABLE revisions ADD CONSTRAINT revisions_entity_kind_check
    CHECK (entity_kind IN ('connector', 'tool', 'server', 'role',
                           'dlp_policy', 'approval_policy', 'identity_provider', 'saml_provider'));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE revisions DROP CONSTRAINT IF EXISTS revisions_entity_kind_check;
DELETE FROM revisions WHERE entity_kind IN ('dlp_policy', 'approval_policy', 'identity_provider', 'saml_provider');
ALTER TABLE revisions ADD CONSTRAINT revisions_entity_kind_check
    CHECK (entity_kind IN ('connector', 'tool', 'server', 'role'));
-- +goose StatementEnd
