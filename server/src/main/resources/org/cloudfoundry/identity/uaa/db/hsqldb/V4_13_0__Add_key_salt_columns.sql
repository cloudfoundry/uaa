ALTER TABLE user_google_mfa_credentials
ADD COLUMN encryption_key_label VARCHAR(255)

ALTER TABLE user_google_mfa_credentials
ADD COLUMN salt VARCHAR(255)

ALTER TABLE user_google_mfa_credentials
ADD COLUMN encrypted_validation_code VARCHAR(255)