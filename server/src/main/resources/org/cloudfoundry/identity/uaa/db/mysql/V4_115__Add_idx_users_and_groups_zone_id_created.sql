CREATE INDEX idx_users_zone_id_created ON users (identity_zone_id, created);

CREATE INDEX idx_groups_zone_id_created ON `groups` (identity_zone_id, created);
