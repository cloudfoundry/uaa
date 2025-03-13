DROP INDEX IF EXISTS idx_users_zone_id_created ON users;
ALTER TABLE users ADD INDEX idx_users_zone_id_created (identity_zone_id, created);

DROP INDEX IF EXISTS idx_group_membership_zone_member_group ON group_membership;
ALTER TABLE group_membership ADD INDEX idx_group_membership_zone_member_group (identity_zone_id, member_id, group_id);

DROP INDEX IF EXISTS idx_group_membership_id_zone_id ON group_membership;
ALTER TABLE group_membership ADD INDEX idx_group_membership_id_zone_id (group_id, identity_zone_id);

DROP INDEX IF EXISTS idx_groups_zone_id_created ON groups;
ALTER TABLE groups ADD INDEX idx_groups_zone_id_created (identity_zone_id, created);

DROP INDEX IF EXISTS idx_external_group_zone_id_created ON external_group_mapping;
ALTER TABLE external_group_mapping ADD INDEX idx_external_group_zone_id_created (group_id, identity_zone_id);