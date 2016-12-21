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
ALTER TABLE oauth_client_details ALTER COLUMN identity_zone_id varchar(36) NOT NULL;
DROP INDEX user_identity_zone ON users;
ALTER TABLE users ALTER COLUMN identity_zone_id varchar(36) NOT NULL;
CREATE NONCLUSTERED INDEX user_identity_zone ON users (identity_zone_id);

DROP INDEX users_unique_key ON users;


CREATE UNIQUE NONCLUSTERED INDEX username_in_idp on users (identity_provider_id, username);

DECLARE @table NVARCHAR(512), @dropconstraintsql NVARCHAR(MAX);

SELECT @table = N'oauth_client_details';

SELECT @dropconstraintsql = 'ALTER TABLE ' + @table 
    + ' DROP CONSTRAINT ' + name + ';'
    FROM sys.key_constraints
    WHERE [type] = 'PK'
    AND [parent_object_id] = OBJECT_ID(@table);

EXEC sp_executeSQL  @dropconstraintsql

ALTER TABLE oauth_client_details ADD PRIMARY KEY (client_id,identity_zone_id);