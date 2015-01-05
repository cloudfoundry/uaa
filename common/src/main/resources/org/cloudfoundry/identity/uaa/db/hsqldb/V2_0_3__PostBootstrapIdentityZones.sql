ALTER TABLE oauth_client_details ALTER COLUMN identity_zone_id SET NOT NULL;
ALTER TABLE users ALTER COLUMN identity_zone_id SET NOT NULL;

DROP INDEX users_unique_key IF EXISTS;
CREATE UNIQUE INDEX username_in_idp ON users (identity_provider_id,username);

ALTER TABLE oauth_client_details DROP PRIMARY KEY;
ALTER TABLE oauth_client_details ADD PRIMARY KEY (client_id,identity_zone_id);