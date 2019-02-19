CREATE TABLE mfa_providers (
  id NVARCHAR(36) NOT NULL ,
  created DATETIME default current_timestamp NOT NULL,
  lastModified DATETIME null,
  identity_zone_id NVARCHAR(36) NOT NULL,
  name NVARCHAR(255) NOT NULL,
  type NVARCHAR(255) NOT NULL,
  config TEXT,
  active BIT not null,
  PRIMARY KEY (id)
);


