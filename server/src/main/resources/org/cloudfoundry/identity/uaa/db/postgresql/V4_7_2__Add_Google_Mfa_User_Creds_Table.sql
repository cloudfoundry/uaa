CREATE TABLE user_google_mfa_credentials (
   user_id VARCHAR(36) NOT NULL    PRIMARY KEY,
   secret_key VARCHAR(255) NOT NULL,
   validation_code INTEGER NOT NULL,
   scratch_codes VARCHAR(255) NOT NULL

);
