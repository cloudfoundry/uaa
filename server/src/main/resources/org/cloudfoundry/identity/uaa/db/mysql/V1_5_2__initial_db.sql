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

CREATE TABLE users (
   id char(36) not null primary key,
   created TIMESTAMP default current_timestamp not null,
   lastModified TIMESTAMP null,
   version BIGINT default 0 not null,
   username VARCHAR(255) not null,
   password VARCHAR(255) not null,
   email VARCHAR(255) not null,
   authorities VARCHAR(1024) default 'uaa.user' not null,
   givenName VARCHAR(255),
   familyName VARCHAR(255),
   active BOOLEAN default true not null,
   phoneNumber VARCHAR(255)
) ;

-- add column with null allowed for existing users
ALTER TABLE users ADD COLUMN verified BOOLEAN;
-- everyone who was here before the column existed gets set to true
UPDATE users SET verified=TRUE WHERE verified IS NULL;
-- modify the column to be default to false and not null
ALTER TABLE users ALTER COLUMN verified SET DEFAULT false;
--  and do not allow null anymore to prevent new users from getting the wrong value
ALTER TABLE users MODIFY verified BOOLEAN NOT NULL;

CREATE UNIQUE INDEX unique_uk_1 on users (username);

CREATE TABLE sec_audit (
   principal_id char(36) not null,
   event_type INTEGER not null,
   origin VARCHAR(255) not null,
   event_data VARCHAR(255),
   created TIMESTAMP default current_timestamp
) ;

CREATE TABLE oauth_client_details (
  client_id VARCHAR(255) PRIMARY KEY,
  resource_ids VARCHAR(1024),
  client_secret VARCHAR(255),
  scope VARCHAR(255),
  authorized_grant_types VARCHAR(255),
  web_server_redirect_uri VARCHAR(1024),
  authorities VARCHAR(255),
  access_token_validity INTEGER default 0,
  refresh_token_validity INTEGER default 0,
  additional_information VARCHAR(4096)
) ;

create table oauth_code (
  code VARCHAR(255),
  authentication BLOB
) ;

CREATE TABLE authz_approvals (
  userName VARCHAR(36) not null,
  clientId VARCHAR(36) not null,
  scope VARCHAR(255) not null,
  expiresAt TIMESTAMP not null DEFAULT '2001-01-01 01:01:01.000001',
  status VARCHAR(50) default 'APPROVED' not null,
  lastModifiedAt TIMESTAMP not null DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  primary key (userName, clientId, scope)
) ;

CREATE TABLE `groups` (
  id VARCHAR(36) not null primary key,
  displayName VARCHAR(255) not null,
  created TIMESTAMP default current_timestamp not null,
  lastModified TIMESTAMP null,
  version INTEGER default 0 not null,
  constraint unique_uk_2 unique(displayName)
) ;

CREATE TABLE group_membership (
  group_id VARCHAR(36) not null,
  member_id VARCHAR(36) not null,
  member_type VARCHAR(8) default 'USER' not null,
  authorities VARCHAR(255) default 'READ' not null,
  added TIMESTAMP default current_timestamp not null,
  primary key (group_id, member_id)
) ;

CREATE TABLE external_group_mapping (
  group_id VARCHAR(36) not null,
  external_group VARCHAR(255) not null,
  added TIMESTAMP default current_timestamp not null,
  primary key (group_id, external_group)
);
