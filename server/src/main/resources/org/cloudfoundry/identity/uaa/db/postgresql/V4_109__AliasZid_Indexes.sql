CREATE INDEX CONCURRENTLY IF NOT EXISTS identity_provider_alias_zid__idx on identity_provider (alias_zid);
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_alias_zid__idx on users (alias_zid);
