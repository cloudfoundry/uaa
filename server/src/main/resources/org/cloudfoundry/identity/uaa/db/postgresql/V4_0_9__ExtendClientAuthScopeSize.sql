ALTER TABLE oauth_client_details ALTER COLUMN scope TYPE VARCHAR(4000);
ALTER TABLE oauth_client_details ALTER COLUMN authorities TYPE VARCHAR(4000);
ALTER TABLE revocable_tokens ALTER COLUMN scope TYPE VARCHAR(4000);
