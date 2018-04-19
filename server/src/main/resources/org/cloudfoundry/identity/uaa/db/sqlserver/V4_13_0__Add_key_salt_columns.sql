ALTER TABLE user_google_mfa_credentials
ADD encryption_key_label VARCHAR(255), salt VARCHAR(255), encrypted_validation_code VARCHAR(255) NULL;

ALTER TABLE user_google_mfa_credentials
ALTER COLUMN validation_code INTEGER NULL;
