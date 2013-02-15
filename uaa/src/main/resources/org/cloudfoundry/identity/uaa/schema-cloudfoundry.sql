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
-- it can be used to maintain the schema on cloudfoundry.com (which
-- uses postgresql).

CREATE TABLE USERS (
   id char(36) not null primary key,
   created TIMESTAMP default current_timestamp,
   lastModified TIMESTAMP default current_timestamp,
   version BIGINT default 0,
   username VARCHAR(255) not null,
   password VARCHAR(255) not null,
   email VARCHAR(255) not null,
   authority BIGINT default 0,
   givenName VARCHAR(255) not null,
   familyName VARCHAR(255) not null
) ;

ALTER TABLE users DROP CONSTRAINT unique_uk_1;
CREATE UNIQUE INDEX unique_uk_1_1 on users (LOWER(username));
ALTER TABLE USERS ADD COLUMN active BOOLEAN default true;
ALTER TABLE USERS ALTER COLUMN created SET NOT NULL;
ALTER TABLE USERS ALTER COLUMN lastModified SET NOT NULL;
ALTER TABLE USERS ALTER COLUMN version SET NOT NULL;
ALTER TABLE USERS ALTER COLUMN authority SET NOT NULL;
ALTER TABLE USERS ADD COLUMN phoneNumber VARCHAR(255);
ALTER TABLE USERS ADD COLUMN authorities VARCHAR(1024) default 'uaa.user';
UPDATE USERS set authorities='uaa.user' where authority=0 and authorities not like '%.%';
UPDATE USERS set authorities='uaa.admin,uaa.user' where authority=1 and authorities not like '%.%';
ALTER TABLE USERS ALTER COLUMN givenName drop not NULL;
ALTER TABLE USERS ALTER COLUMN familyName drop not NULL;

CREATE TABLE SEC_AUDIT (
   principal_id char(36) not null,
   event_type INTEGER not null,
   origin VARCHAR(255) not null,
   event_data VARCHAR(255),
   created TIMESTAMP default current_timestamp
) ;

CREATE INDEX audit_principal ON SEC_AUDIT (principal_id);
CREATE INDEX audit_created ON SEC_AUDIT (created);

CREATE TABLE OAUTH_CLIENT_DETAILS (
  client_id VARCHAR(256) PRIMARY KEY,
  resource_ids VARCHAR(1024),
  client_secret VARCHAR(256),
  scope VARCHAR(256),
  authorized_grant_types VARCHAR(256),
  web_server_redirect_uri VARCHAR(1024),
  authorities VARCHAR(256),
  access_token_validity INTEGER
) ;

ALTER TABLE OAUTH_CLIENT_DETAILS ADD COLUMN refresh_token_validity INTEGER default 0;
ALTER TABLE OAUTH_CLIENT_DETAILS ADD COLUMN additional_information VARCHAR(4096);

CREATE TABLE GROUPS (
  id VARCHAR(36) not null primary key,
  displayName VARCHAR(255) not null,
  created TIMESTAMP default current_timestamp not null,
  lastModified TIMESTAMP default current_timestamp not null,
  version BIGINT default 0 not null,
  constraint unique_uk_2 unique(displayName)
) ;

CREATE TABLE GROUP_MEMBERSHIP (
  group_id VARCHAR(36) not null,
  member_id VARCHAR(36) not null,
  member_type VARCHAR(8) not null default 'USER',
  authorities VARCHAR(255) not null default 'READ',
  added TIMESTAMP default current_timestamp not null,
  primary key (group_id, member_id)
) ;

create table oauth_client_token (
  token_id VARCHAR(256),
  token BYTEA,
  authentication_id VARCHAR(256),
  user_name VARCHAR(256),
  client_id VARCHAR(256)
) ;

create table oauth_access_token (
  token_id VARCHAR(256),
  token BYTEA,
  authentication_id VARCHAR(256),
  user_name VARCHAR(256),
  client_id VARCHAR(256),
  authentication BYTEA,
  refresh_token VARCHAR(256)
) ;

create table oauth_refresh_token (
  token_id VARCHAR(256),
  token BYTEA,
  authentication BYTEA
) ;

create table oauth_code (
  code VARCHAR(256), authentication BYTEA
) ;

CREATE TABLE AUTHZ_APPROVALS (
  userName VARCHAR(36) not null,
  clientId VARCHAR(36) not null,
  scope VARCHAR(255) not null,
  expiresAt TIMESTAMP default current_timestamp not null,
  status VARCHAR(50) default 'APPROVED' not null,
  lastModifiedAt TIMESTAMP default current_timestamp not null,
  primary key (userName, clientId, scope)
) ;

DROP TABLE oauth_client_token;
DROP TABLE oauth_access_token;
DROP TABLE oauth_refresh_token;
