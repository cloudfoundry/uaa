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
-- column that holds the origin of the user, something like 'uaa' or 'ldap' or 'keystone'
ALTER TABLE users ADD origin varchar(36) default 'uaa' NOT NULL;
-- track a users external user ID. For LDAP it is the DN or UID
ALTER TABLE users ADD external_id varchar(255) default NULL;

-- redo the unique key
DROP INDEX unique_uk_1 ON users;
-- add a user_id column to
CREATE UNIQUE INDEX users_unique_key ON users (username, origin);

CREATE TABLE new_authz_approvals (
  user_id VARCHAR(36) not null,
  client_id VARCHAR(36) not null,
  scope VARCHAR(255) not null,
  expiresat DATETIME not null DEFAULT '2001-01-01 01:01:01.000001',
  status VARCHAR(50) default 'APPROVED' not null,
  lastmodifiedat DATETIME not null DEFAULT CURRENT_TIMESTAMP ,
  primary key (user_id, client_id, scope)
);


DROP TRIGGER set_authz_approvals_last_updated_at;


INSERT INTO new_authz_approvals SELECT u.id, a.clientid, a.scope, a.expiresat, a.status, a.lastmodifiedat FROM
  users u, authz_approvals a where a.username = u.username;

EXEC sp_rename 'authz_approvals', 'authz_approvals_old';
EXEC sp_rename 'new_authz_approvals', 'authz_approvals';

GO
CREATE TRIGGER set_authz_approvals_last_updated_at ON authz_approvals
AFTER UPDATE 
AS
BEGIN
  UPDATE authz_approvals
  SET lastmodifiedat = CURRENT_TIMESTAMP
  FROM Inserted i
  WHERE authz_approvals.user_id = i.user_id AND authz_approvals.client_id = i.client_id AND authz_approvals.scope=i.scope;
END

