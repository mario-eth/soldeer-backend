-- Add up migration script here

ALTER TABLE projects
ALTER COLUMN downloads TYPE BIGINT;

ALTER TABLE revisions
ALTER COLUMN downloads TYPE BIGINT;