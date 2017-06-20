-- HSQLDB does not support indices with function - but we create this one to keep it in synch with the other schemas
CREATE INDEX revocable_tokens_zone_id ON revocable_tokens(identity_zone_id);