--
-- Cloud Foundry
-- Copyright (c) [2015] Pivotal Software, Inc. All Rights Reserved.
--
-- This product is licensed to you under the Apache License, Version 2.0 (the "License").
-- You may not use this product except in compliance with the License.
--
-- This product includes a number of subcomponents with
-- separate copyright notices and license terms. Your use of these
-- subcomponents is subject to the terms and conditions of the
-- subcomponent's license, as noted in the LICENSE file.
--

ALTER TABLE oauth_code ADD COLUMN created TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL;
ALTER TABLE oauth_code ADD COLUMN expiresat BIGINT DEFAULT 0 NOT NULL;
ALTER TABLE oauth_code ADD COLUMN user_id VARCHAR(36) NULL;
ALTER TABLE oauth_code ADD COLUMN client_id VARCHAR(36) NULL;
