-- Add up migration script here

CREATE TABLE "verifications" (
    id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
    user_id UUID NOT NULL REFERENCES users(id),
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP
            WITH
                TIME ZONE DEFAULT NOW()
);

CREATE INDEX verifications_user_id_index ON verifications (user_id);