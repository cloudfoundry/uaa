ALTER TABLE oauth_client_details ADD COLUMN lastmodified TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL;

ALTER TABLE identity_provider CHANGE lastModified lastmodified TIMESTAMP NULL;

ALTER TABLE identity_zone CHANGE lastModified lastmodified TIMESTAMP NULL;