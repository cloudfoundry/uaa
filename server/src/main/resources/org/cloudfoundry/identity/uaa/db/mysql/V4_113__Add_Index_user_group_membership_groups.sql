CREATE INDEX idx_users_zone_id_created ON users (identity_zone_id, created);

CREATE INDEX idx_group_membership_zone_member_group ON group_membership (identity_zone_id, member_id, group_id);

CREATE INDEX idx_group_membership_id_zone_id ON group_membership (group_id, identity_zone_id);

CREATE INDEX idx_groups_zone_id_created ON `groups` (identity_zone_id, created);

CREATE INDEX idx_external_group_zone_id_created ON external_group_mapping (group_id, identity_zone_id);
