-- Add up migration script here

CREATE TABLE "organizations" (
    id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
    name VARCHAR(100) NOT NULL,
    description TEXT DEFAULT 'No Description',
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add organization_id to projects table to associate projects with organizations
ALTER TABLE projects
ADD COLUMN organization_id UUID REFERENCES organizations(id);

CREATE INDEX idx_projects_organization_id ON projects(organization_id);

-- Rename user_id to created_by and drop foreign key constraint
ALTER TABLE projects
DROP CONSTRAINT IF EXISTS projects_user_id_fkey;

ALTER TABLE projects
RENAME COLUMN user_id TO created_by;

ALTER TABLE projects
ADD CONSTRAINT projects_created_by_fkey FOREIGN KEY (created_by) REFERENCES users(id);


