-- Create index without CONCURRENTLY to allow execution within a transaction
-- CONCURRENTLY cannot be used inside a transaction, which causes hangs with newer Flyway versions
-- The IF NOT EXISTS clause prevents errors if the index already exists
CREATE UNIQUE INDEX IF NOT EXISTS users_unique_key_lower ON users (LOWER(origin),LOWER(username),LOWER(identity_zone_id));