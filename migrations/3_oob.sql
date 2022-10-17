ALTER TABLE users
ADD oob_secret BYTEA;

ALTER TABLE users
DROP COLUMN hash;
