--
-- These tables were previously dropped in https://github.com/cloudfoundry/uaa/pull/2717
-- Restoring them here due to https://github.com/cloudfoundry/uaa/issues/2789
-- Can consider dropping these again in the future (e.g. at UAA V78/79, when most users
-- will no longer experience issue #2789)
--

CREATE TABLE mfa_providers (
  id CHAR(36) NOT NULL PRIMARY KEY,
  created TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  lastmodified TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  identity_zone_id varchar(36) NOT NULL,
  name varchar(255) NOT NULL,
  type varchar(255) NOT NULL,
  config LONGVARCHAR
);

CREATE TABLE user_google_mfa_credentials (
  user_id VARCHAR(36) NOT NULL,
  secret_key VARCHAR(255) NOT NULL,
  validation_code INTEGER,
  scratch_codes VARCHAR(255) NOT NULL,
  mfa_provider_id CHAR(36) NOT NULL,
  zone_id CHAR(36) NOT NULL,
  encryption_key_label VARCHAR(255),
  encrypted_validation_code VARCHAR(255) NULL,
  PRIMARY KEY (user_id,mfa_provider_id)
);
