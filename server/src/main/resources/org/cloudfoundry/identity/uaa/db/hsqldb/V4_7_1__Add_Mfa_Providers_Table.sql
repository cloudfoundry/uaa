CREATE TABLE mfa_providers (
  id CHAR(36) NOT NULL PRIMARY KEY,
  active BOOLEAN NOT NULL,
  created TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  lastmodified TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  identity_zone_id varchar(36) NOT NULL,
  name varchar(255) NOT NULL,
  type varchar(255) NOT NULL,
  config LONGVARCHAR
);
