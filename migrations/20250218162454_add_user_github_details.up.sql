-- Add up migration script here
ALTER TABLE users
ADD COLUMN github_id TEXT,
ADD COLUMN github_username TEXT;
