CREATE INDEX identity_provider_alias_zid_idz_id__idx on identity_provider (alias_zid, identity_zone_id) LOCK = SHARED;
CREATE INDEX users_alias_zid_idz_id__idx on users (alias_zid, identity_zone_id) LOCK = SHARED;
