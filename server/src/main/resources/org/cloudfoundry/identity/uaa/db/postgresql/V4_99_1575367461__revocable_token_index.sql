CREATE INDEX CONCURRENTLY IF NOT EXISTS revocable_tokens_user_id_client_id_response_type_identity__idx on revocable_tokens(user_id, client_id, response_type, identity_zone_id);
