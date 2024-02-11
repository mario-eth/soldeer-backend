-- Add down migration script here

DROP TABLE IF EXISTS verifications;
DROP INDEX IF EXISTS verifications_user_id_index;