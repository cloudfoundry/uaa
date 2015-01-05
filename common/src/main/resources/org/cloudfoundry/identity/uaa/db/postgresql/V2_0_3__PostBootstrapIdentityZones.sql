ALTER TABLE oauth_client_details ALTER COLUMN identity_zone_id SET NOT NULL;
ALTER TABLE users ALTER COLUMN identity_zone_id SET NOT NULL;

DROP INDEX IF EXISTS users_unique_key;
CREATE UNIQUE INDEX username_in_idp ON users (identity_provider_id,LOWER(username));

ALTER TABLE oauth_client_details DROP CONSTRAINT oauth_client_details_pkey;
ALTER TABLE oauth_client_details ADD PRIMARY KEY (client_id,identity_zone_id);
