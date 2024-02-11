-- Add up migration script here

ALTER TABLE revisions
ADD COLUMN downloads INT DEFAULT 0;
