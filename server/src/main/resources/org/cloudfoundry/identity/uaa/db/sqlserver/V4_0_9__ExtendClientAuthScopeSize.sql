ALTER TABLE oauth_client_details ALTER COLUMN scope NVARCHAR(4000);
ALTER TABLE oauth_client_details ALTER COLUMN authorities NVARCHAR(4000);
ALTER TABLE revocable_tokens ALTER COLUMN scope NVARCHAR(4000);


