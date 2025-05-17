-- Add down migration script here

-- Remove organization_id from projects
DROP INDEX IF EXISTS idx_projects_organization_id;
ALTER TABLE projects DROP COLUMN IF EXISTS organization_id;

-- Drop organization members table and its indexes
DROP INDEX IF EXISTS idx_organization_members_user_id;
DROP INDEX IF EXISTS idx_organization_members_org_id;

-- Drop organizations table
DROP TABLE IF EXISTS organizations;
