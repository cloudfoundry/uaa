--
-- Cloud Foundry 2012.02.03 Beta
-- Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
--
-- This product is licensed to you under the Apache License, Version 2.0 (the "License").
-- You may not use this product except in compliance with the License.
--
-- This product includes a number of subcomponents with
-- separate copyright notices and license terms. Your use of these
-- subcomponents is subject to the terms and conditions of the
-- subcomponent's license, as noted in the LICENSE file.
--
-- Creates tables and adds constraints and columns incrementally, so
-- it can be used to maintain the schema on cloudfoundry.com

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

CREATE UNIQUE INDEX unique_uk_1 on users (username);

CREATE TABLE sec_audit (
   principal_id char(36) not null,
   event_type INTEGER not null,
   origin VARCHAR(255) not null,
   event_data VARCHAR(255),
   created TIMESTAMP default current_timestamp
) ;

CREATE TABLE oauth_client_details (
  client_id VARCHAR(256) PRIMARY KEY,
  resource_ids VARCHAR(1024),
  client_secret VARCHAR(256),
  scope VARCHAR(256),
  authorized_grant_types VARCHAR(256),
  web_server_redirect_uri VARCHAR(1024),
  authorities VARCHAR(256),
  access_token_validity INTEGER default 0,
  refresh_token_validity INTEGER default 0,
  additional_information VARCHAR(4096)
) ;

create table oauth_code (
  code VARCHAR(256),
  authentication BLOB
) ;
 
CREATE TABLE authz_approvals (
  userName VARCHAR(36) not null,
  clientId VARCHAR(36) not null,
  scope VARCHAR(255) not null,
  expiresAt TIMESTAMP not null,
  status VARCHAR(50) default 'APPROVED' not null,
  lastModifiedAt TIMESTAMP not null,
  primary key (userName, clientId, scope)
) ;

CREATE TABLE groups (
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
