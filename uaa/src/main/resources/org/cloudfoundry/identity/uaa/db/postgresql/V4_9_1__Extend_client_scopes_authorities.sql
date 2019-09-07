ALTER TABLE oauth_client_details ALTER COLUMN scope TYPE TEXT;
ALTER TABLE oauth_client_details ALTER COLUMN authorities TYPE TEXT;
ALTER TABLE revocable_tokens ALTER COLUMN scope TYPE TEXT;
