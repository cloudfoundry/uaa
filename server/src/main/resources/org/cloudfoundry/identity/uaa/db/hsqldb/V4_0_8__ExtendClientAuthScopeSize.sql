ALTER TABLE oauth_client_details ALTER COLUMN scope VARCHAR(4096);
ALTER TABLE oauth_client_details ALTER COLUMN authorities VARCHAR(4096);
ALTER TABLE revocable_tokens ALTER COLUMN scope VARCHAR(4096);
