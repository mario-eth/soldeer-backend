-- Add up migration script here
ALTER TABLE "users"
    ADD COLUMN username VARCHAR(50) NOT NULL UNIQUE DEFAULT 'user' || CAST(floor(random() * 9000000000 + 1000000000) AS VARCHAR);

CREATE INDEX users_username_idx ON users (username);

UPDATE users SET role = 'owner';