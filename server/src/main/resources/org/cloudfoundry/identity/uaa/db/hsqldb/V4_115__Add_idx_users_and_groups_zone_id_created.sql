-- Create indexes to match MySQL/PostgreSQL migrations
CREATE INDEX IF NOT EXISTS idx_users_zone_id_created ON users (identity_zone_id, created);

CREATE INDEX IF NOT EXISTS idx_groups_zone_id_created ON groups (identity_zone_id, created);