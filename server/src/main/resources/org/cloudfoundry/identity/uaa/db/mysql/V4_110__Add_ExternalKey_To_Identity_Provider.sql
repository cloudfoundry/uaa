-- add column external_key for oauth2,oidc,saml2 IdPs
ALTER TABLE identity_provider ADD COLUMN external_key VARCHAR(512) DEFAULT NULL;
CREATE UNIQUE INDEX external_key_in_zone on identity_provider (identity_zone_id,type(36),external_key) LOCK = SHARED;