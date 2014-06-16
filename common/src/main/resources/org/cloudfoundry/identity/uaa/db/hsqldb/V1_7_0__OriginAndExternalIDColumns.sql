-- column that holds the origin of the user, something like 'uaa' or 'ldap' or 'keystone'
ALTER TABLE users ADD COLUMN origin varchar(36) default 'uaa' NOT NULL;
-- track a users external user ID. For LDAP it is the DN or UID
ALTER TABLE users ADD COLUMN external_id varchar(255) default NULL;

-- redo the unique key
DROP INDEX unique_uk_1 IF EXISTS;
-- add a user_id column to
CREATE UNIQUE INDEX users_unique_key ON users (username, origin);

CREATE TABLE new_authz_approvals (
  user_id VARCHAR(36) NOT NULL,
  client_id VARCHAR(36) NOT NULL,
  scope VARCHAR(255) NOT NULL,
  expiresat TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  status VARCHAR(50) DEFAULT 'APPROVED' NOT NULL,
  lastmodifiedat TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  primary key (user_id, client_id, scope)
) ;

INSERT INTO new_authz_approvals SELECT u.id, a.clientid, a.scope, a.expiresat, a.status, a.lastmodifiedat FROM
  users u, authz_approvals a where a.username = u.username;

ALTER TABLE authz_approvals RENAME TO authz_approvals_old;

ALTER TABLE new_authz_approvals RENAME TO authz_approvals;
