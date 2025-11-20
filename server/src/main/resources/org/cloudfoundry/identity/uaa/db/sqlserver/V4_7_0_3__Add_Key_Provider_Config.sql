CREATE TABLE key_provider_config (
   id CHAR(36) NOT NULL PRIMARY KEY,
   identity_zone_id NVARCHAR(36) NOT NULL,
   client_id NVARCHAR(256),
   dcs_tenant_id NVARCHAR(256),
   created DATETIME DEFAULT current_timestamp not null
) ;

CREATE UNIQUE INDEX key_provider_config_idx ON key_provider_config (identity_zone_id);