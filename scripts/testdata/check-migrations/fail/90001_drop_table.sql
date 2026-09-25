-- expect: 5: DROP TABLE widgets
-- expect-note: and a section in
-- +goose Up
CREATE TABLE gadgets (id text PRIMARY KEY);
DROP TABLE IF EXISTS widgets;
-- +goose Down
DROP TABLE gadgets;
