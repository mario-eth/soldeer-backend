-- Add down migration script here
DROP INDEX IF EXISTS users_username_idx;
ALTER TABLE "users" DROP COLUMN IF EXISTS username;
