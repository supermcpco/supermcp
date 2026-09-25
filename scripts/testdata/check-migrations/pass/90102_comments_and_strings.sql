-- +goose Up
-- DROP TABLE widgets; in a line comment
/* DROP TABLE widgets; TRUNCATE widgets;
   in a block comment */
COMMENT ON TABLE widgets IS 'DROP TABLE widgets; DELETE FROM widgets';
COMMENT ON COLUMN widgets.colour IS $$ ALTER TABLE widgets RENAME TO w $$;
SELECT E'\'; DROP TABLE widgets; --';
INSERT INTO settings (key, value) VALUES ('note', 'TRUNCATE is a word');
