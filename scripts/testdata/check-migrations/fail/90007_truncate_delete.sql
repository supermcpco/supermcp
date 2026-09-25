-- expect: 4: TRUNCATE widgets
-- expect: 5: DELETE FROM gadgets
-- +goose Up
TRUNCATE TABLE widgets;
DELETE FROM ONLY gadgets WHERE id <> '';
