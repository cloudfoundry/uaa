ALTER TABLE oauth_client_details ALTER COLUMN scope TYPE VARCHAR(3072);
ALTER TABLE oauth_client_details ALTER COLUMN authorities TYPE VARCHAR(3072);
ALTER TABLE revocable_tokens ALTER COLUMN scope TYPE VARCHAR(3072);