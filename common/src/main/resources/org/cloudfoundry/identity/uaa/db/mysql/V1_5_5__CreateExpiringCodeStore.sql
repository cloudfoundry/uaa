--
-- Cloud Foundry 
-- Copyright (c) [2014] Pivotal Software, Inc. All Rights Reserved.
--
-- This product is licensed to you under the Apache License, Version 2.0 (the "License").
-- You may not use this product except in compliance with the License.
--
-- This product includes a number of subcomponents with
-- separate copyright notices and license terms. Your use of these
-- subcomponents is subject to the terms and conditions of the
-- subcomponent's license, as noted in the LICENSE file.
--

CREATE TABLE expiring_code_store (
  code VARCHAR(255) NOT NULL PRIMARY KEY,
  expiresat BIGINT NOT NULL,
  data MEDIUMTEXT NOT NULL
);
