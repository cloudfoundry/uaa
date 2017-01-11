ALTER TABLE oauth_client_details ALTER COLUMN scope VARCHAR(3072);
ALTER TABLE oauth_client_details ALTER COLUMN authorities VARCHAR(3072);
ALTER TABLE revocable_tokens ALTER COLUMN scope VARCHAR(3072);