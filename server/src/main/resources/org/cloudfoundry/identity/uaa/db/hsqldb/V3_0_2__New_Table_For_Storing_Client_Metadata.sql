CREATE TABLE oauth_client_metadata (
  id VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL UNIQUE,
  identity_zone_id VARCHAR(36) NOT NULL,
  show_on_home_page BOOLEAN DEFAULT TRUE NOT NULL,
  app_launch_url VARCHAR(1024),
  app_icon BLOB,
  version INT DEFAULT 0 NOT NULL,
  PRIMARY KEY (id),
  CONSTRAINT FK_client_details FOREIGN KEY (client_id,identity_zone_id) REFERENCES oauth_client_details(client_id,identity_zone_id)
);
