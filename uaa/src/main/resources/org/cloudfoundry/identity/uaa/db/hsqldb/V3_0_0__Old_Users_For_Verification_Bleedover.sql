ALTER TABLE users ADD COLUMN legacy_verification_behavior BOOLEAN DEFAULT FALSE NOT NULL;
UPDATE users SET legacy_verification_behavior = TRUE;
