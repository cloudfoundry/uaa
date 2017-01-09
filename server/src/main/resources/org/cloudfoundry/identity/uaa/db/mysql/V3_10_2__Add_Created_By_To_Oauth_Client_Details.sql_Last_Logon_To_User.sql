ALTER TABLE oauth_client_details ADD COLUMN created_by CHAR(36) DEFAULT NULL;
ALTER TABLE oauth_client_details ADD COLUMN last_updated_by CHAR(36) DEFAULT NULL;

