CREATE TABLE mfa_providers (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  created TIMESTAMP default current_timestamp NOT NULL,
  lastModified TIMESTAMP null,
  identity_zone_id VARCHAR(36) NOT NULL,
  name VARCHAR(255) NOT NULL,
  type VARCHAR(255) NOT NULL,
  config TEXT,
  active BOOLEAN NOT NULL
);