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

-- add zone id to the groups table
ALTER TABLE groups ADD COLUMN identity_zone_id varchar(36) DEFAULT 'uaa' NOT NULL ;
ALTER TABLE groups DROP CONSTRAINT unique_uk_2;
CREATE UNIQUE INDEX groups_unique_key ON groups (displayname,identity_zone_id);
