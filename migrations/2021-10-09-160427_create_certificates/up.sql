-- Your SQL goes here
CREATE TABLE certificates (
	id UUID PRIMARY KEY,
	x509 BYTEA NOT NULL,
	chain TEXT NOT NULL,
	key BYTEA NOT NULL,
	not_before TIMESTAMPTZ NOT NULL,
	not_after TIMESTAMPTZ NOT NULL
);