-- add columns for alias-id and alias-zone-id
ALTER TABLE identity_provider
    ADD COLUMN alias_id VARCHAR(36) DEFAULT NULL;
ALTER TABLE identity_provider
    ADD COLUMN alias_zid VARCHAR(36) DEFAULT NULL;