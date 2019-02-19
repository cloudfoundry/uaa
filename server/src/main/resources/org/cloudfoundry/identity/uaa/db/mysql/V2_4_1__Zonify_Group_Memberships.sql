--
-- Cloud Foundry
-- Copyright (c) [2015] Pivotal Software, Inc. All Rights Reserved.
--
-- This product is licensed to you under the Apache License, Version 2.0 (the "License").
-- You may not use this product except in compliance with the License.
--
-- This product includes a number of subcomponents with
-- separate copyright notices and license terms. Your use of these
-- subcomponents is subject to the terms and conditions of the
-- subcomponent's license, as noted in the LICENSE file.
--

ALTER TABLE group_membership ADD COLUMN identity_zone_id varchar(36) DEFAULT 'uaa';
ALTER TABLE group_membership DROP PRIMARY KEY;
ALTER TABLE group_membership ADD COLUMN `id` int(11) unsigned PRIMARY KEY AUTO_INCREMENT;

ALTER TABLE external_group_mapping ADD COLUMN identity_zone_id varchar(36);
ALTER TABLE external_group_mapping ADD COLUMN origin varchar(36);
ALTER TABLE external_group_mapping DROP PRIMARY KEY;
ALTER TABLE external_group_mapping ADD COLUMN `id` int(11) unsigned PRIMARY KEY AUTO_INCREMENT;

UPDATE group_membership SET identity_zone_id = (SELECT identity_zone_id FROM users where users.id = group_membership.member_id);
UPDATE group_membership SET identity_zone_id = (SELECT 'uaa' FROM groups where groups.id = group_membership.member_id);

UPDATE external_group_mapping SET identity_zone_id = 'uaa', origin='ldap';

ALTER TABLE group_membership ADD UNIQUE KEY group_membership_unique_key(identity_zone_id,member_id,group_id);
ALTER TABLE external_group_mapping ADD UNIQUE KEY external_group_unique_key(identity_zone_id,origin,external_group,group_id);
