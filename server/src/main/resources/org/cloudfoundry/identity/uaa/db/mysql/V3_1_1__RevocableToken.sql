--
-- Cloud Foundry 
-- Copyright (c) [2016] Pivotal Software, Inc. All Rights Reserved.
--
-- This product is licensed to you under the Apache License, Version 2.0 (the "License").
-- You may not use this product except in compliance with the License.
--
-- This product includes a number of subcomponents with
-- separate copyright notices and license terms. Your use of these
-- subcomponents is subject to the terms and conditions of the
-- subcomponent's license, as noted in the LICENSE file.
--

CREATE TABLE revocable_tokens (

  token_id VARCHAR(36) NOT NULL PRIMARY KEY,
  client_id VARCHAR(255) NOT NULL,
  user_id VARCHAR(36),
  format VARCHAR(255),
  response_type VARCHAR(25) NOT NULL,
  issued_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  scope VARCHAR(1000),
  data MEDIUMTEXT NOT NULL
);

CREATE INDEX idx_revocable_token_client_id ON revocable_tokens(client_id);

CREATE INDEX idx_revocable_token_user_id ON revocable_tokens(user_id);

CREATE INDEX idx_revocable_token_expires_at ON revocable_tokens(expires_at);
