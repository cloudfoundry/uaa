-- in mysql we turn off lower function during queries
CREATE INDEX revocable_tokens_zone_id ON revocable_tokens(identity_zone_id);