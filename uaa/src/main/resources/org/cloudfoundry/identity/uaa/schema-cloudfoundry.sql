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
   familyName VARCHAR(255) not null,
   constraint unique_uk_1 unique(username)
) ;

ALTER TABLE USERS ADD COLUMN active BOOLEAN default true;
ALTER TABLE USERS ALTER COLUMN created SET NOT NULL;
ALTER TABLE USERS ALTER COLUMN lastModified SET NOT NULL;
ALTER TABLE USERS ALTER COLUMN version SET NOT NULL;
ALTER TABLE USERS ALTER COLUMN authority SET NOT NULL;
ALTER TABLE USERS ADD COLUMN phoneNumber VARCHAR(255);
ALTER TABLE USERS ADD COLUMN authorities VARCHAR(1024) default 'uaa.user';
UPDATE USERS set authorities='uaa.user' where authority=0;
UPDATE USERS set authorities='uaa.admin,uaa.user' where authority=1;

CREATE TABLE SEC_AUDIT (
   principal_id char(36) not null,
   event_type INTEGER not null,
   origin VARCHAR(255) not null,
   event_data VARCHAR(255),
   created TIMESTAMP default current_timestamp
) ;

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
