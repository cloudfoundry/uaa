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
CREATE TABLE identity_zone (
  id varchar(36) NOT NULL,
  created DATETIME default current_timestamp not null,
  lastModified DATETIME null,
  version BIGINT default 0 not null,
  subdomain varchar(255) NOT NULL,
  name varchar(255) NOT NULL,
  description varchar(max),
  PRIMARY KEY (id),
  CONSTRAINT subdomain UNIQUE(subdomain)
);

CREATE TABLE identity_provider (
  id varchar(36) NOT NULL,
  created DATETIME default current_timestamp not null,
  lastModified DATETIME null,
  version BIGINT default 0 not null,
  identity_zone_id varchar(36) NOT NULL,
  name varchar(255) NOT NULL,
  origin_key varchar(255) NOT NULL,
  type varchar(255) NOT NULL,
  config varchar(max),
  PRIMARY KEY (id),
  CONSTRAINT key_in_zone UNIQUE(identity_zone_id, origin_key)
);

ALTER TABLE users ADD identity_provider_id varchar(36) DEFAULT NULL;
ALTER TABLE users ADD identity_zone_id varchar(36) DEFAULT 'uaa';

CREATE NONCLUSTERED INDEX user_identity_zone ON users (identity_zone_id);

-- we would do this later, when we're ready to remove users.origin
-- ALTER TABLE users drop key users_unique_key; ALTER TABLE users DROP COLUMN origin;

ALTER TABLE group_membership ADD identity_provider_id varchar(36) DEFAULT NULL;
CREATE NONCLUSTERED INDEX identity_provider_id ON group_membership (identity_provider_id);

ALTER TABLE oauth_client_details ADD identity_zone_id varchar(36) DEFAULT 'uaa';

CREATE TABLE client_idp (
  client_id varchar(255) NOT NULL,
  identity_provider_id varchar(36) NOT NULL,
  PRIMARY KEY (client_id,identity_provider_id)
);
