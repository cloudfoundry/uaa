-- HSQLDB does not support indices with function - but we create this one to keep it in synch with the other schemas
CREATE INDEX active_in_zone ON identity_provider (identity_zone_id,active);
