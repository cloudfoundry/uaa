--
-- Copyright (c) [2016] Microsoft, Inc. All Rights Reserved.
--
-- This product is licensed to you under the Apache License, Version 2.0 (the "License").
-- You may not use this product except in compliance with the License.
--
-- This product includes a number of subcomponents with
-- separate copyright notices and license terms. Your use of these
-- subcomponents is subject to the terms and conditions of the
-- subcomponent's license, as noted in the LICENSE file.
--
CREATE TABLE service_provider (
  id VARCHAR(36) NOT NULL,
  created DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
  lastmodified DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
  version BIGINT DEFAULT 0 NOT NULL,
  identity_zone_id VARCHAR(36) NOT NULL,
  name VARCHAR(255) NOT NULL,
  entity_id VARCHAR(255) NOT NULL,
  config varchar(max),
  active BIT DEFAULT 1 NOT NULL,
  PRIMARY KEY (id)
);


CREATE UNIQUE INDEX entity_in_zone on service_provider (identity_zone_id, entity_id);
