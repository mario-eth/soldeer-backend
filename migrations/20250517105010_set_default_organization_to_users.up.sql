-- Add up migration script here
-- Create default organization for each user
INSERT INTO organizations (name, description)
SELECT 'Default' || u.username, 'Default organization for user ' || u.username
FROM users u;

-- Add organization_id column to users table
ALTER TABLE users ADD COLUMN organization_id UUID REFERENCES organizations(id);

-- Set the default organization for each user
UPDATE users u
SET organization_id = (
    SELECT o.id
    FROM organizations o
    WHERE o.name = 'Default' || u.username
    LIMIT 1
);

-- Update projects to link to the user's default organization
UPDATE projects p
SET organization_id = (
    SELECT organization_id
    FROM users u
    WHERE u.id = p.created_by
);
