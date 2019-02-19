DECLARE @table NVARCHAR(512), @dropconstraintsql NVARCHAR(MAX);

SELECT @table = N'user_google_mfa_credentials';

SELECT @dropconstraintsql = 'ALTER TABLE ' + @table
    + ' DROP CONSTRAINT ' + name + ';'
    FROM sys.key_constraints
    WHERE [type] = 'PK'
    AND [parent_object_id] = OBJECT_ID(@table);

EXEC sp_executeSQL  @dropconstraintsql

ALTER TABLE user_google_mfa_credentials ADD PRIMARY KEY (user_id,mfa_provider_id);
