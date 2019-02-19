--
-- Cloud Foundry
-- Copyright (c) [2016] Pivotal Software, Inc. All Rights Reserved.
--
-- This product is licensed to you under the Apache License, Version 2.0 (the "License").
-- You may not use this product except in compliance with the License.
--
-- This product includes a number of subcomponents with
-- separate copyright notices and license terms. Your use of these
-- subcomponents is subject to the terms and conditions of the
-- subcomponent's license, as noted in the LICENSE file.
--


-- create a lower index to match the query
CREATE UNIQUE INDEX groups_unique_lower_key ON groups(LOWER(displayname),LOWER(identity_zone_id));