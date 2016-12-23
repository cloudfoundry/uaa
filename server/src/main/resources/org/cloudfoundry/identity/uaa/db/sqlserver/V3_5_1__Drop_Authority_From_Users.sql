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
DECLARE  @dropconstraintsql NVARCHAR(MAX);
SELECT @dropconstraintsql = 'ALTER TABLE users' + 
    + ' DROP CONSTRAINT ' + name + ';'
    FROM sys.default_constraints
    where [parent_object_id] = OBJECT_ID(N'users') and [parent_column_id] = COLUMNPROPERTY(OBJECT_ID(N'users'),(N'authority'),'ColumnId')
EXEC sp_executeSQL @dropconstraintsql

ALTER TABLE users DROP COLUMN authority;