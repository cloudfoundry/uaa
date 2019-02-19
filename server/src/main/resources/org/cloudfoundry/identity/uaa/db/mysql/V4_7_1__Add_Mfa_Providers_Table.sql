CREATE TABLE `mfa_providers` (
  `id` varchar(36) NOT NULL,
  `created` TIMESTAMP default current_timestamp NOT NULL,
  `lastModified` TIMESTAMP null,
  `identity_zone_id` varchar(36) NOT NULL,
  `name` varchar(255) NOT NULL,
  `type` varchar(255) NOT NULL,
  `config` longtext,
  `active` BOOLEAN NOT NULL,
  PRIMARY KEY (`id`)
);
