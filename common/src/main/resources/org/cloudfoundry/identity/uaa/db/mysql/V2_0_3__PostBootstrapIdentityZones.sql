ALTER TABLE oauth_client_details MODIFY COLUMN `identity_zone_id` varchar(36) NOT NULL;
ALTER TABLE users MODIFY COLUMN `identity_zone_id` varchar(36) NOT NULL;