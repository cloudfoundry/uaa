-- add column external_key for oauth2,oidc,saml2 IdPs
ALTER TABLE identity_provider ADD COLUMN external_key TEXT DEFAULT NULL;
CREATE UNIQUE INDEX identity_provider_ext_key_zid__idx on identity_provider (identity_zone_id,type,external_key);