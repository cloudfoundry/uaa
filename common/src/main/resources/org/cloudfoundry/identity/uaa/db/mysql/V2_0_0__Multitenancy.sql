CREATE TABLE `identity_zone` (
  `id` varchar(36) NOT NULL,
  `created` TIMESTAMP default current_timestamp not null,
  `lastModified` TIMESTAMP null,
  `version` BIGINT default 0 not null,
  `subdomain` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` longtext,
  PRIMARY KEY (`id`),
  UNIQUE KEY `subdomain` (`subdomain`)
);

CREATE TABLE `identity_provider` (
  `id` varchar(36) NOT NULL,
  `created` TIMESTAMP default current_timestamp not null,
  `lastModified` TIMESTAMP null,
  `version` BIGINT default 0 not null,
  `identity_zone_id` varchar(36) NOT NULL,
  `name` varchar(255) NOT NULL,
  `origin_key` varchar(255) NOT NULL,
  `type` varchar(255) NOT NULL,
  `config` longtext,
  PRIMARY KEY (`id`),
  UNIQUE KEY `key_in_zone` (`identity_zone_id`,`origin_key`)
);

ALTER TABLE users ADD COLUMN identity_provider_id varchar(36) DEFAULT NULL;
ALTER TABLE users ADD COLUMN identity_zone_id varchar(36) DEFAULT NULL;

ALTER TABLE users ADD KEY `user_identity_zone` (`identity_zone_id`);
-- we would do this later, when we're ready to remove users.origin
-- ALTER TABLE users drop key users_unique_key; ALTER TABLE users DROP COLUMN `origin`;

ALTER TABLE group_membership ADD COLUMN identity_provider_id varchar(36) DEFAULT NULL;
ALTER TABLE group_membership ADD KEY `identity_provider_id` (`identity_provider_id`);

ALTER TABLE oauth_client_details ADD COLUMN `identity_zone_id` varchar(36) DEFAULT NULL;

CREATE TABLE `client_idp` (
  `client_id` varchar(255) NOT NULL,
  `identity_provider_id` varchar(36) NOT NULL,
  PRIMARY KEY (`client_id`,`identity_provider_id`)
);
