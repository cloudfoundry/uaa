ALTER TABLE oauth_client_details MODIFY scope LONGTEXT;
ALTER TABLE oauth_client_details MODIFY authorities LONGTEXT;
ALTER TABLE revocable_tokens MODIFY scope LONGTEXT;
