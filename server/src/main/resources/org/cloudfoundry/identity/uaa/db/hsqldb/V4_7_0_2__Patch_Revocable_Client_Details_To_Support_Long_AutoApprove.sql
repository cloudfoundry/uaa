ALTER TABLE oauth_client_details ALTER COLUMN autoapprove LONGVARCHAR;
ALTER TABLE oauth_client_details ALTER COLUMN autoapprove SET DEFAULT NULL;
ALTER TABLE oauth_client_details ALTER COLUMN web_server_redirect_uri LONGVARCHAR;
