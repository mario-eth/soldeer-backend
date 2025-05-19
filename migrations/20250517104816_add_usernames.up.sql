-- Add up migration script here
ALTER TABLE "users" ADD COLUMN username VARCHAR(50);
UPDATE "users" SET username = CASE 
    WHEN github_username IS NOT NULL THEN github_username
    ELSE 'user' || CAST(floor(random() * 9000000000 + 1000000000) AS VARCHAR)
END;
ALTER TABLE "users" ALTER COLUMN username SET NOT NULL;
ALTER TABLE "users" ADD CONSTRAINT users_username_unique UNIQUE (username);

CREATE INDEX users_username_idx ON users (username);

UPDATE users SET role = 'owner';