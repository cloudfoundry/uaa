ALTER TABLE user_google_mfa_credentials
ADD COLUMN encryption_key_label VARCHAR(255),
ADD COLUMN salt VARCHAR(255)