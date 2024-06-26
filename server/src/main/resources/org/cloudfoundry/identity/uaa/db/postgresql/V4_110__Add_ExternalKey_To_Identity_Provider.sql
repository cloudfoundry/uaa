-- add column external_key for oauth2,oidc,saml2 IdPs
ALTER TABLE identity_provider ADD COLUMN external_key TEXT DEFAULT NULL;
CREATE UNIQUE INDEX external_key_in_zone on identity_provider (identity_zone_id,type,external_key) WHERE external_key IS NOT NULL;