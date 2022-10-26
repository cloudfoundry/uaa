ALTER TABLE oauth_client_details MODIFY scope VARCHAR(4000);
ALTER TABLE revocable_tokens MODIFY scope VARCHAR(4000);
