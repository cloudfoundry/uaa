CREATE TABLE service_provider (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  created TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  lastmodified TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  version BIGINT DEFAULT 0,
  identity_zone_id VARCHAR(36) NOT NULL,
  name VARCHAR(255) NOT NULL,
  entity_id VARCHAR(255) NOT NULL,
  config TEXT,
  active BOOLEAN DEFAULT TRUE NOT NULL
);

CREATE UNIQUE INDEX entity_in_zone ON service_provider (identity_zone_id,entity_id);
