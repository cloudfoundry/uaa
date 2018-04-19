ALTER TABLE user_google_mfa_credentials
ADD COLUMN encryption_key_label VARCHAR(255),
ADD COLUMN encrypted_validation_code VARCHAR(255) NULL;

ALTER TABLE user_google_mfa_credentials
MODIFY COLUMN validation_code INTEGER NULL;