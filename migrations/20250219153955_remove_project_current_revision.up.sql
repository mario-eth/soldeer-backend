-- Add up migration script here
ALTER TABLE projects
DROP COLUMN IF EXISTS current_revision;