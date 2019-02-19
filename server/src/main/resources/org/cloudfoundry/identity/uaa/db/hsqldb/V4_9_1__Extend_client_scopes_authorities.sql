ALTER TABLE oauth_client_details ALTER COLUMN scope CLOB;
ALTER TABLE oauth_client_details ALTER COLUMN authorities CLOB;
ALTER TABLE revocable_tokens ALTER COLUMN scope CLOB;
