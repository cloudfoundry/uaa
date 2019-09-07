ALTER TABLE user_google_mfa_credentials DROP PRIMARY KEY;
ALTER TABLE user_google_mfa_credentials ADD PRIMARY KEY (user_id,mfa_provider_id);