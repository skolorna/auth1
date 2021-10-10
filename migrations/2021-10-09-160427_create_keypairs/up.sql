-- Your SQL goes here
CREATE TABLE keypairs (
	id UUID PRIMARY KEY,
	public BYTEA NOT NULL,
	private BYTEA NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);