CREATE TABLE key_provider_config (
   id CHAR(36) NOT NULL PRIMARY KEY,
   identity_zone_id varchar(36) NOT NULL,
   client_id VARCHAR(256),
   dcs_tenant_id VARCHAR(256),
   created TIMESTAMP default current_timestamp NOT NULL
) ;

CREATE UNIQUE INDEX key_provider_config_idx ON key_provider_config (identity_zone_id);