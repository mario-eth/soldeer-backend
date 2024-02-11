-- Add down migration script here

ALTER TABLE verifications
DROP COLUMN verification_type;