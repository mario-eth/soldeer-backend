-- Add up migration script here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE
    "users" (
        id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
        email VARCHAR(255) NOT NULL UNIQUE,
        verified BOOLEAN NOT NULL DEFAULT FALSE,
        password VARCHAR(100) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'user',
        created_at TIMESTAMP
            WITH
                TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP
            WITH
                TIME ZONE DEFAULT NOW()
    );

CREATE INDEX users_email_idx ON users (email);

CREATE TABLE
    "projects" (
        id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
        name VARCHAR(100) NOT NULL,
        description TEXT NOT NULL,
        github_url TEXT NOT NULL,
        deleted BOOLEAN NOT NULL DEFAULT FALSE,
        current_revision UUID,
        user_id UUID NOT NULL REFERENCES users(id),
        created_at TIMESTAMP
            WITH
                TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP
            WITH
                TIME ZONE DEFAULT NOW()
    );

-- Add an index on the foreign key for better performance
CREATE INDEX idx_projects_user_id ON projects(user_id);


CREATE TABLE
    "revisions" (
        id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
        version VARCHAR(100) NOT NULL,
        internal_name TEXT NOT NULL,
        url TEXT NOT NULL,
        project_id UUID NOT NULL REFERENCES projects(id),
        deleted BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMP
            WITH
                TIME ZONE DEFAULT NOW()
    );

-- Add an index on the foreign key for better performance
CREATE INDEX idx_revisions_user_id ON revisions(project_id);