-- column that holds the origin of the user, something like 'uaa' or 'ldap' or 'keystone'
ALTER TABLE users ADD COLUMN origin varchar(36) default 'uaa' NOT NULL;
-- track a users external user ID. For LDAP it is the DN or UID
ALTER TABLE users ADD COLUMN external_id varchar(255) default NULL;

-- redo the unique key
DROP INDEX unique_uk_1 ON users;
-- add a user_id column to
CREATE UNIQUE INDEX users_unique_key ON users (username, origin);

CREATE TABLE new_authz_approvals (
  user_id VARCHAR(36) not null,
  client_id VARCHAR(36) not null,
  scope VARCHAR(255) not null,
  expiresat TIMESTAMP not null,
  status VARCHAR(50) default 'APPROVED' not null,
  lastmodifiedat TIMESTAMP not null,
  primary key (user_id, client_id, scope)
) ;

INSERT INTO new_authz_approvals SELECT u.id, a.clientid, a.scope, a.expiresat, a.status, a.lastmodifiedat FROM
  users u, authz_approvals a where a.username = u.username;

ALTER TABLE authz_approvals RENAME TO authz_approvals_old;

ALTER TABLE new_authz_approvals RENAME TO authz_approvals;


