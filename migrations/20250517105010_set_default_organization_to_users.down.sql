-- Add down migration script here
-- Add down migration script here
-- Remove organization_id from users table
ALTER TABLE users DROP COLUMN IF EXISTS organization_id;

-- Update projects to remove organization_id (already handled in add_organization.down.sql)

-- Remove default organizations
DELETE FROM organizations 
WHERE name = 'Default';
