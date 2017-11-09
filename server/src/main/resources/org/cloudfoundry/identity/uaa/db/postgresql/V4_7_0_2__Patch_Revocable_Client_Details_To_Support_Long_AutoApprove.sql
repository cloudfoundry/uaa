ALTER TABLE oauth_client_details ALTER COLUMN autoapprove TYPE TEXT;
ALTER TABLE oauth_client_details ALTER COLUMN autoapprove SET DEFAULT NULL;
ALTER TABLE oauth_client_details ALTER COLUMN web_server_redirect_uri TYPE TEXT;
