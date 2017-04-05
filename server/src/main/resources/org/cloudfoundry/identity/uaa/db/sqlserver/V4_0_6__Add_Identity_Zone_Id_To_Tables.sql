--
-- Cloud Foundry
-- Copyright (c) [2017] Pivotal Software, Inc. All Rights Reserved.
--
-- This product is licensed to you under the Apache License, Version 2.0 (the "License").
-- You may not use this product except in compliance with the License.
--
-- This product includes a number of subcomponents with
-- separate copyright notices and license terms. Your use of these
-- subcomponents is subject to the terms and conditions of the
-- subcomponent's license, as noted in the LICENSE file.
--

ALTER TABLE group_membership ADD identity_zone_id nvarchar(36) DEFAULT NULL;
GO
UPDATE group_membership SET identity_zone_id = (SELECT identity_zone_id from groups WHERE group_membership.group_id = groups.id);

ALTER TABLE external_group_mapping ADD identity_zone_id nvarchar(36) DEFAULT NULL;
GO
UPDATE external_group_mapping SET identity_zone_id = (SELECT identity_zone_id from groups WHERE external_group_mapping.group_id = groups.id);

ALTER TABLE oauth_code ADD identity_zone_id nvarchar(36) DEFAULT NULL;
GO
UPDATE oauth_code SET identity_zone_id = (SELECT identity_zone_id from users WHERE oauth_code.user_id = users.id);
