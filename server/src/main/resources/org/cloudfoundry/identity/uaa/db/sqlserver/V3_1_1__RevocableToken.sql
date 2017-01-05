--
-- Copyright (c) [2016] Cloud Foundry Foundation. All Rights Reserved.
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
  token_id NVARCHAR(36) NOT NULL PRIMARY KEY,
  client_id NVARCHAR(255) NOT NULL,
  user_id NVARCHAR(36),
  format NVARCHAR(255),
  response_type NVARCHAR(25) NOT NULL,
  issued_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  scope NVARCHAR(1000),
  data NVARCHAR(max) NOT NULL
);

CREATE INDEX idx_revocable_token_client_id ON revocable_tokens(client_id);

CREATE INDEX idx_revocable_token_user_id ON revocable_tokens(user_id);

CREATE INDEX idx_revocable_token_expires_at ON revocable_tokens(expires_at);
