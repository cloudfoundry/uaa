--
-- These tables were previously dropped in https://github.com/cloudfoundry/uaa/pull/2717
-- Restoring them here due to https://github.com/cloudfoundry/uaa/issues/2789
--
-- Can consider dropping these again in the future (e.g. at UAA V78/79, when most users
-- will no longer experience issue #2789)
--

CREATE TABLE IF NOT EXISTS mfa_providers (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  created TIMESTAMP default current_timestamp NOT NULL,
  lastModified TIMESTAMP null,
  identity_zone_id VARCHAR(36) NOT NULL,
  name VARCHAR(255) NOT NULL,
  type VARCHAR(255) NOT NULL,
  config TEXT
);

CREATE TABLE IF NOT EXISTS user_google_mfa_credentials (
  user_id VARCHAR(36) NOT NULL PRIMARY KEY,
  secret_key VARCHAR(255) NOT NULL,
  validation_code INTEGER,
  scratch_codes VARCHAR(255) NOT NULL,
  mfa_provider_id CHAR(36) NOT NULL,
  zone_id CHAR(36) NOT NULL,
  encryption_key_label VARCHAR(255),
  encrypted_validation_code VARCHAR(255) NULL
);

