ALTER TABLE oauth_client_details MODIFY scope TEXT;
ALTER TABLE oauth_client_details MODIFY authorities TEXT;
ALTER TABLE revocable_tokens MODIFY scope VARCHAR(4096);
