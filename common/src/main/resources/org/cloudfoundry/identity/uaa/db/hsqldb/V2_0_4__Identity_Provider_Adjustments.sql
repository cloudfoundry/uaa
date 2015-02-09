--
-- Cloud Foundry
-- Copyright (c) [2014] Pivotal Software, Inc. All Rights Reserved.
--
-- This product is licensed to you under the Apache License, Version 2.0 (the "License").
-- You may not use this product except in compliance with the License.
--
-- This product includes a number of subcomponents with
-- separate copyright notices and license terms. Your use of these
-- subcomponents is subject to the terms and conditions of the
-- subcomponent's license, as noted in the LICENSE file.
--

-- modify the column to be 36 characters to match users.origin
ALTER TABLE identity_provider ALTER COLUMN origin_key varchar(36);

-- add an active column to the identity_provider table
ALTER TABLE identity_provider ADD COLUMN active BOOLEAN DEFAULT TRUE NOT NULL;

-- drop the index dependent on the identity_provider_id column
DROP INDEX username_in_idp IF EXISTS;

-- drop the column
ALTER TABLE users DROP COLUMN identity_provider_id;

-- unique is still username,origin,zone_id
CREATE UNIQUE INDEX users_unique_key ON users (origin,username,identity_zone_id);

-- drop previous index
DROP INDEX identity_provider_id IF EXISTS;

-- drop redundant IDP column
ALTER TABLE group_membership DROP COLUMN identity_provider_id;
