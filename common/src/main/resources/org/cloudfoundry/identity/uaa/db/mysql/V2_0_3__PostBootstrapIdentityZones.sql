ALTER TABLE oauth_client_details MODIFY COLUMN `identity_zone_id` char(36) NOT NULL;
ALTER TABLE users MODIFY COLUMN `identity_zone_id` SET NOT NULL;