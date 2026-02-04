-- Create index without CONCURRENTLY to allow execution within a transaction
-- CONCURRENTLY cannot be used inside a transaction, which causes hangs with newer Flyway versions
-- The IF NOT EXISTS clause prevents errors if the index already exists
CREATE INDEX IF NOT EXISTS users_key_lower_wo_origin ON users (LOWER(username),LOWER(identity_zone_id));
