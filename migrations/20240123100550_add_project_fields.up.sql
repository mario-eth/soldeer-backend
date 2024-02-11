-- Add up migration script here

ALTER TABLE projects
ADD COLUMN downloads INT DEFAULT 0,
ADD COLUMN image TEXT,
ADD COLUMN long_description TEXT;