ALTER TABLE oauth_client_details MODIFY COLUMN `identity_zone_id` varchar(36) NOT NULL;
ALTER TABLE users MODIFY COLUMN `identity_zone_id` varchar(36) NOT NULL;

DROP INDEX users_unique_key ON users;
ALTER TABLE users ADD UNIQUE KEY `username_in_idp` (`identity_provider_id`,`username`);

ALTER TABLE oauth_client_details DROP PRIMARY KEY;
ALTER TABLE oauth_client_details ADD PRIMARY KEY (`client_id`,`identity_zone_id`);