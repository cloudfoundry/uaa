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

-- modify the column to be 36 characters to match users.origin
--CONSTRAINT key_in_zone UNIQUE(identity_zone_id, origin_key)
ALTER TABLE identity_provider DROP CONSTRAINT key_in_zone
ALTER TABLE identity_provider ALTER COLUMN origin_key varchar(36) NOT NULL;
ALTER TABLE identity_provider ADD CONSTRAINT key_in_zone UNIQUE NONCLUSTERED(identity_zone_id, origin_key)
-- add an active column to the identity_provider table
ALTER TABLE identity_provider ADD active BIT DEFAULT 1 NOT NULL;

-- drop the index dependent on the identity_provider_id column
DROP INDEX username_in_idp ON users;

-- drop the column
DECLARE  @dropconstraintsql NVARCHAR(MAX);
SELECT @dropconstraintsql = 'ALTER TABLE users' + 
    + ' DROP CONSTRAINT ' + name + ';'
    FROM sys.default_constraints
    where [parent_object_id] = OBJECT_ID(N'users') and [parent_column_id] = COLUMNPROPERTY(OBJECT_ID(N'users'),(N'identity_provider_id'),'ColumnId')
EXEC sp_executeSQL @dropconstraintsql

ALTER TABLE users DROP COLUMN identity_provider_id;

-- unique is still username,origin,zone_id
CREATE UNIQUE NONCLUSTERED INDEX users_unique_key on users (origin,username,identity_zone_id);

-- drop previous index
DROP INDEX identity_provider_id ON group_membership;

-- drop redundant IDP column
SELECT @dropconstraintsql = 'ALTER TABLE group_membership' + 
    + ' DROP CONSTRAINT ' + name + ';'
    FROM sys.default_constraints
    where [parent_object_id] = OBJECT_ID(N'group_membership') and [parent_column_id] = COLUMNPROPERTY(OBJECT_ID(N'group_membership'),(N'identity_provider_id'),'ColumnId')
EXEC sp_executeSQL @dropconstraintsql

ALTER TABLE group_membership DROP COLUMN identity_provider_id;
