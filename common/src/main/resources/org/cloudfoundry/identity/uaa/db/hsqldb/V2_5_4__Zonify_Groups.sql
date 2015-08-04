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

-- remove zone id from the group_membership table - it is derived from group_id
DROP INDEX group_membership_unique_key;
ALTER TABLE group_membership DROP COLUMN identity_zone_id;
CREATE UNIQUE INDEX group_membership_unique_key ON group_membership (member_id,group_id);

-- remove zone id from the external_grou_mapping table - it is derived from group_id
DROP INDEX external_group_unique_key;
ALTER TABLE external_group_mapping DROP COLUMN identity_zone_id;
CREATE UNIQUE INDEX external_group_unique_key ON external_group_mapping (origin,external_group,group_id);
