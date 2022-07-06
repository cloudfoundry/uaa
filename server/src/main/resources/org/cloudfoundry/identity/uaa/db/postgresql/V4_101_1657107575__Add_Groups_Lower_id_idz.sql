create index concurrently IF NOT EXISTS id_identityzone_lower ON groups (lower(id), lower(identity_zone_id));
