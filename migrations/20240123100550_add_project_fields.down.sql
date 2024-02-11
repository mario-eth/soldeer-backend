-- Add down migration script here
ALTER TABLE projects
DROP COLUMN downloads,
DROP COLUMN image,
DROP COLUMN long_description;

