ALTER TABLE oauth_client_details MODIFY scope VARCHAR(3072);
ALTER TABLE oauth_client_details MODIFY authorities VARCHAR(3072);
ALTER TABLE revocable_tokens MODIFY scope VARCHAR(3072);