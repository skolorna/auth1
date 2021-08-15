-- Your SQL goes here
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(320) UNIQUE NOT NULL,
		email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO users (email, hash, created_at)
	VALUES ('user@example.com', 'invalid', NOW());
