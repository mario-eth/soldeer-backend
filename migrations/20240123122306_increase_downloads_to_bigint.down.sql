-- Add down migration script here

ALTER TABLE projects
ALTER COLUMN downloads TYPE INT;

ALTER TABLE revisions
ALTER COLUMN downloads TYPE INT;
```