-- expect: 6: DROP TABLE widgets
-- +goose Up
-- A quote inside an E'' string, a doubled quote and a block comment must
-- not swallow the statement after them.
SELECT E'it\'s', 'it''s', "odd""name" /* a /* nested */ comment */;
DROP TABLE widgets;
