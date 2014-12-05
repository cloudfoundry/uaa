CREATE TABLE identity_zone (
  id CHAR(36) NOT NULL PRIMARY KEY,
  created TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  lastmodified TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  version BIGINT DEFAULT 0 NOT NULL,
  subdomain varchar(255) NOT NULL,
  name varchar(255) NOT NULL,
  description LONGVARCHAR NULL
);

CREATE UNIQUE INDEX subdomain ON identity_zone (subdomain);

CREATE TABLE identity_provider (
  id CHAR(36) NOT NULL PRIMARY KEY,
  created TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  lastmodified TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  version BIGINT DEFAULT 0 NOT NULL,
  identity_zone_id varchar(36) NOT NULL,
  name varchar(255) NOT NULL,
  origin_key varchar(255) NOT NULL,
  type varchar(255) NOT NULL,
  config LONGVARCHAR
);

CREATE UNIQUE INDEX key_in_zone ON identity_provider (identity_zone_id,origin_key);

ALTER TABLE users ADD COLUMN identity_provider_id CHAR(36) DEFAULT NULL;
ALTER TABLE users ADD COLUMN identity_zone_id varchar(36) DEFAULT NULL;

DROP INDEX users_unique_key IF EXISTS;
CREATE UNIQUE INDEX username_in_idp ON users (identity_provider_id,username);
-- we would do this later, when we're ready to remove users.origin
-- ALTER TABLE users drop key users_unique_key; ALTER TABLE users DROP COLUMN origin;
CREATE INDEX user_identity_zone ON users (identity_zone_id);
ALTER TABLE group_membership ADD COLUMN identity_provider_id CHAR(36) DEFAULT NULL;
CREATE INDEX identity_provider_id ON group_membership (identity_provider_id);

ALTER TABLE oauth_client_details ADD COLUMN identity_zone_id CHAR(36) DEFAULT NULL;
ALTER TABLE oauth_client_details DROP PRIMARY KEY;
ALTER TABLE oauth_client_details ADD PRIMARY KEY (client_id,identity_zone_id);

CREATE TABLE client_idp (
  client_id varchar(255) NOT NULL,
  identity_provider_id CHAR(36) NOT NULL,
  PRIMARY KEY (client_id,identity_provider_id)
);
