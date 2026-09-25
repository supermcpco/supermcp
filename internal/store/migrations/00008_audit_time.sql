-- supermcp:breaking (deletes every audit event and anchor; docs/UPGRADING.md,
-- "migration 00008" under 1.0.0)
-- +goose Up
-- +goose StatementBegin

-- The write time was outside the hash chain, and the chain is what decides
-- whether a record can be trusted. Two consequences, both demonstrated
-- against a live instance before this change:
--
--   * A row could be backdated through the maintenance role and still
--     verify, so the record of when something happened was not evidence of
--     anything.
--   * Retention deletes by age, and the cut takes everything at or below
--     the newest row older than the window. One backdated row near the head
--     therefore dragged the whole stream into a deletion that afterwards
--     looked entirely lawful: five of six rows went, the survivor verified,
--     and the anchor said it was routine.
--
-- The timestamp is now written by the application rather than defaulted by
-- the database, and it is covered by the row's hash. Rows written before
-- this change hash without it and cannot be verified, so they are removed
-- rather than left as permanently broken links. No released version wrote
-- them.

DELETE FROM audit_anchors;
DELETE FROM audit_events;

ALTER TABLE audit_events ALTER COLUMN ts DROP DEFAULT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE audit_events ALTER COLUMN ts SET DEFAULT now();
-- +goose StatementEnd
