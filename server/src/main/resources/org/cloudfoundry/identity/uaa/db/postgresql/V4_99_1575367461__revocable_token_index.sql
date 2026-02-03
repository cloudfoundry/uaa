-- Create index without CONCURRENTLY to allow execution within a transaction
-- CONCURRENTLY cannot be used inside a transaction, which causes hangs with newer Flyway versions
-- The IF NOT EXISTS clause prevents errors if the index already exists
CREATE INDEX IF NOT EXISTS revocable_tokens_user_id_client_id_response_type_identity__idx
    ON revocable_tokens(user_id, client_id, response_type, identity_zone_id);