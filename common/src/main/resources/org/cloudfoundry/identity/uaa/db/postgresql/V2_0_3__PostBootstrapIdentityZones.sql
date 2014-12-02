ALTER TABLE oauth_client_details ALTER COLUMN identity_zone_id SET NOT NULL;
ALTER TABLE users ALTER COLUMN identity_zone_id SET NOT NULL;