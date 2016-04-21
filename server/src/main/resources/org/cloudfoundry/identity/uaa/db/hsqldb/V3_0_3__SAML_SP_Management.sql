CREATE TABLE service_provider (
  id CHAR(36) NOT NULL PRIMARY KEY,
  created TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  lastmodified TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  version BIGINT DEFAULT 0 NOT NULL,
  identity_zone_id varchar(36) NOT NULL,
  name varchar(255) NOT NULL,
  entity_id varchar(255) NOT NULL,
  config LONGVARCHAR,
  active BOOLEAN DEFAULT TRUE NOT NULL
);

CREATE UNIQUE INDEX entity_in_zone ON service_provider (identity_zone_id,entity_id);
