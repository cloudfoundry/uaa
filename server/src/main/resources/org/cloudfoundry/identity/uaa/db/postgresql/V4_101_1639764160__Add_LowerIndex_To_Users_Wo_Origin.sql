CREATE INDEX CONCURRENTLY IF NOT EXISTS users_key_lower_wo_origin ON users (LOWER(username),LOWER(identity_zone_id));
