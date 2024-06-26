CREATE INDEX alias_in_zone on identity_provider (identity_zone_id, alias_zid) LOCK = SHARED;
