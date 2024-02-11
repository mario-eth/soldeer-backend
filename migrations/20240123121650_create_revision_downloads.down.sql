-- Add down migration script here
ALTER TABLE revisions
DROP COLUMN downloads;

