-- Add up migration script here

ALTER TABLE verifications
ADD COLUMN verification_type VARCHAR(50) NOT NULL DEFAULT 'verification';