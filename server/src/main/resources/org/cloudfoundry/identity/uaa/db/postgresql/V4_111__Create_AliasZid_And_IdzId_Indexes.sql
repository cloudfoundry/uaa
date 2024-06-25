CREATE INDEX CONCURRENTLY IF NOT EXISTS identity_provider_alias_zid_idz_id__idx on identity_provider (alias_zid, identity_zone_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_alias_zid_idz_id__idx on users (alias_zid, identity_zone_id);
