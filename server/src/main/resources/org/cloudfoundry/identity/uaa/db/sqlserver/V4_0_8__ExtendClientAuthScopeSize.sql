ALTER TABLE oauth_client_details ALTER COLUMN scope NVARCHAR(MAX);
ALTER TABLE oauth_client_details ALTER COLUMN authorities NVARCHAR(MAX);
ALTER TABLE revocable_tokens ALTER COLUMN scope NVARCHAR(4096);


