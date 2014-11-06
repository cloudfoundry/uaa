-- making everything CHAR(36) ascii will make indexes 1/3 the size,
-- so you can do more in memory and comparisons are proportionately faster.
ALTER TABLE `authz_approvals` 
MODIFY COLUMN `user_id` CHAR(36) CHARACTER SET ascii,
MODIFY COLUMN `client_id` CHAR(36) CHARACTER SET ascii;

ALTER TABLE `client_idp` 
MODIFY COLUMN `client_id` CHAR(36) CHARACTER SET ascii,
MODIFY COLUMN `identity_provider_id` CHAR(36) CHARACTER SET ascii;

ALTER TABLE `external_group_mapping` 
MODIFY COLUMN `group_id` CHAR(36) CHARACTER SET ascii;

ALTER TABLE `group_membership` 
MODIFY COLUMN `group_id` CHAR(36) CHARACTER SET ascii,
MODIFY COLUMN `member_id` CHAR(36) CHARACTER SET ascii;

ALTER TABLE `groups` 
MODIFY COLUMN `id` CHAR(36) CHARACTER SET ascii;

ALTER TABLE `identity_provider` 
MODIFY COLUMN `id` CHAR(36) CHARACTER SET ascii,
MODIFY COLUMN `identity_zone_id` CHAR(36) CHARACTER SET ascii;

ALTER TABLE `identity_zone` 
MODIFY COLUMN `id` CHAR(36) CHARACTER SET ascii,
MODIFY COLUMN `service_instance_id` CHAR(36) CHARACTER SET ascii;

ALTER TABLE `oauth_client_details` 
MODIFY COLUMN `client_id` CHAR(36) CHARACTER SET ascii,
MODIFY COLUMN `identity_zone_id` CHAR(36) CHARACTER SET ascii;

ALTER TABLE `users` 
MODIFY COLUMN `id` CHAR(36) CHARACTER SET ascii,
MODIFY COLUMN `identity_provider_id` CHAR(36) CHARACTER SET ascii;


