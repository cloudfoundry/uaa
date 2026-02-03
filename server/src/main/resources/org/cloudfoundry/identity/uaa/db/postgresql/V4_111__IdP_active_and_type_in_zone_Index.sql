-- Create index without CONCURRENTLY to allow execution within a transaction
-- CONCURRENTLY cannot be used inside a transaction, which causes hangs with newer Flyway versions
-- The IF NOT EXISTS clause prevents errors if the index already exists
CREATE INDEX IF NOT EXISTS active_and_type_in_zone on identity_provider (identity_zone_id, active, type);