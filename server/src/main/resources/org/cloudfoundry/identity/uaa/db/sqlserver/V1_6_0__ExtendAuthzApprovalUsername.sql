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

DECLARE @table NVARCHAR(512), @dropconstraintsql NVARCHAR(MAX);

SELECT @table = N'authz_approvals';

SELECT @dropconstraintsql = 'ALTER TABLE ' + @table 
    + ' DROP CONSTRAINT ' + name + ';'
    FROM sys.key_constraints
    WHERE [type] = 'PK'
    AND [parent_object_id] = OBJECT_ID(@table);

EXEC sp_executeSQL  @dropconstraintsql

ALTER TABLE authz_approvals ALTER COLUMN username VARCHAR(255) NOT NULL;

ALTER TABLE authz_approvals ADD CONSTRAINT PK_authz_approvals PRIMARY KEY CLUSTERED (username ASC, clientid ASC, scope ASC);