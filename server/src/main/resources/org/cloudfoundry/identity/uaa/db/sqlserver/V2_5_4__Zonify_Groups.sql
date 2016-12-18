--
-- Copyright (c) [2016] Microsoft, Inc. All Rights Reserved.
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
DROP INDEX group_membership_unique_key ON group_membership;

-- drop the column
DECLARE  @dropconstraintsql NVARCHAR(MAX);
SELECT @dropconstraintsql = 'ALTER TABLE group_membership' + 
    + ' DROP CONSTRAINT ' + name + ';'
    FROM sys.default_constraints
    where [parent_object_id] = OBJECT_ID(N'group_membership') and [parent_column_id] = COLUMNPROPERTY(OBJECT_ID(N'group_membership'),(N'identity_zone_id'),'ColumnId')
EXEC sp_executeSQL @dropconstraintsql

ALTER TABLE group_membership DROP COLUMN identity_zone_id;
CREATE UNIQUE NONCLUSTERED  INDEX group_membership_unique_key on group_membership(member_id,group_id);

-- remove zone id from the external_group_mapping table - it is derived from group_id
DROP INDEX external_group_unique_key ON external_group_mapping;
ALTER TABLE external_group_mapping DROP COLUMN identity_zone_id;
CREATE UNIQUE NONCLUSTERED  INDEX external_group_unique_key on external_group_mapping(origin,external_group,group_id);