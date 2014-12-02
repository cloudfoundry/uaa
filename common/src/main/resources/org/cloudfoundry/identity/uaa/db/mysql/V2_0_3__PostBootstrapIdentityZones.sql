ALTER TABLE oauth_client_details MODIFY COLUMN `identity_zone_id` char(36) NOT NULL;
ALTER TABLE users MODIFY COLUMN `identity_zone_id` CHAR(36) CHARACTER SET ascii NOT NULL;