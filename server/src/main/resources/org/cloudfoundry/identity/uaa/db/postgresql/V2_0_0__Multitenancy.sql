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
CREATE TABLE identity_zone (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  created TIMESTAMP DEFAULT current_timestamp,
  lastmodified TIMESTAMP DEFAULT current_timestamp,
  version BIGINT DEFAULT 0,
  subdomain VARCHAR(255) NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT
);

CREATE UNIQUE INDEX subdomain ON identity_zone (subdomain);

CREATE TABLE identity_provider (
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  created TIMESTAMP default current_timestamp,
  lastModified TIMESTAMP default current_timestamp,
  version BIGINT default 0,
  identity_zone_id VARCHAR(36) NOT NULL,
  name VARCHAR(255) NOT NULL,
  origin_key VARCHAR(255) NOT NULL,
  type VARCHAR(255) NOT NULL,
  config TEXT
);

CREATE UNIQUE INDEX key_in_zone ON identity_provider (identity_zone_id,origin_key);

ALTER TABLE users ADD COLUMN identity_provider_id VARCHAR(36) DEFAULT NULL;
ALTER TABLE users ADD COLUMN identity_zone_id VARCHAR(36) DEFAULT 'uaa';

-- we would do this later, when we're ready to remove users.origin
-- ALTER TABLE users DROP COLUMN origin;
CREATE INDEX user_identity_zone ON users (identity_zone_id);
ALTER TABLE group_membership ADD COLUMN identity_provider_id VARCHAR(36) DEFAULT NULL;
CREATE INDEX identity_provider_id ON group_membership (identity_provider_id);

ALTER TABLE oauth_client_details ADD COLUMN identity_zone_id VARCHAR(36) DEFAULT 'uaa';

CREATE TABLE client_idp (
  client_id varchar(255) NOT NULL,
  identity_provider_id VARCHAR(36) NOT NULL,
  PRIMARY KEY (client_id,identity_provider_id)
);
