CREATE TABLE service_provider (
  id VARCHAR(36) NOT NULL,
  created TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  lastmodified TIMESTAMP NULL,
  version BIGINT DEFAULT 0 NOT NULL,
  identity_zone_id VARCHAR(36) NOT NULL,
  name VARCHAR(255) NOT NULL,
  entity_id VARCHAR(255) NOT NULL,
  config LONGTEXT,
  active BOOLEAN DEFAULT TRUE NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY entity_in_zone (identity_zone_id, entity_id)
);
