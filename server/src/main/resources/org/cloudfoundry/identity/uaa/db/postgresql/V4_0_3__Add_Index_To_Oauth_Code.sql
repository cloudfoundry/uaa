--
-- Cloud Foundry
-- Copyright (c) [2017] Pivotal Software, Inc. All Rights Reserved.
--
-- This product is licensed to you under the Apache License, Version 2.0 (the "License").
-- You may not use this product except in compliance with the License.
--
-- This product includes a number of subcomponents with
-- separate copyright notices and license terms. Your use of these
-- subcomponents is subject to the terms and conditions of the
-- subcomponent's license, as noted in the LICENSE file.
--


CREATE UNIQUE INDEX oauth_code_uq_idx ON oauth_code(code);
CREATE INDEX oauth_code_expiresat_idx ON oauth_code(expiresat);