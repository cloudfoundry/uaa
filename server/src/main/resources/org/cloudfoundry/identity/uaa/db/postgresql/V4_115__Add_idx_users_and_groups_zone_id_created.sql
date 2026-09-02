-- Create index without CONCURRENTLY to allow execution within a transaction
-- CONCURRENTLY cannot be used inside a transaction, which causes hangs with newer Flyway versions
-- The IF NOT EXISTS clause prevents errors if the index already exists
CREATE INDEX IF NOT EXISTS idx_users_zone_id_created ON users (identity_zone_id, created);

CREATE INDEX IF NOT EXISTS idx_groups_zone_id_created ON "groups" (identity_zone_id, created);
