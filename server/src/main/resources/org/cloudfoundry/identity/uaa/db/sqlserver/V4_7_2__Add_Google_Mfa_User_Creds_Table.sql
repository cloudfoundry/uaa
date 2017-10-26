CREATE TABLE user_google_mfa_credentials (
   user_id NVARCHAR(36) NOT NULL,
   secret_key NVARCHAR(255) NOT NULL,
   validation_code INTEGER NOT NULL,
   scratch_codes NVARCHAR(255) NOT NULL,
   PRIMARY KEY (user_id)
);
