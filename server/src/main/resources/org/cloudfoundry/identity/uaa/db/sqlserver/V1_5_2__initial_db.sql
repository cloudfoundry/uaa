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

CREATE TABLE users (
   id char(36) not null primary key,
   created DATETIME DEFAULT current_timestamp not null,
   lastmodified DATETIME DEFAULT current_timestamp null,
   version BIGINT DEFAULT 0 not null,
   username VARCHAR(255) not null,
   password VARCHAR(255) not null,
   email VARCHAR(255) not null,
   authority BIGINT DEFAULT 0 not null,
   givenname VARCHAR(255),
   familyname VARCHAR(255),
   active BIT DEFAULT 1 not null,
   phonenumber VARCHAR(255),
   authorities VARCHAR(1024) DEFAULT 'uaa.user',
   verified BIT DEFAULT 0 NOT NULL
);

CREATE UNIQUE INDEX unique_uk_1 on users (username);

CREATE TABLE sec_audit (
   principal_id char(36) not null,
   event_type INTEGER not null,
   origin VARCHAR(255) not null,
   event_data VARCHAR(255),
   created DATETIME default current_timestamp
) ;

CREATE TABLE oauth_client_details (
  client_id VARCHAR(255) PRIMARY KEY,
  resource_ids VARCHAR(1024),
  client_secret VARCHAR(256),
  scope VARCHAR(255),
  authorized_grant_types VARCHAR(255),
  web_server_redirect_uri VARCHAR(1024),
  authorities VARCHAR(255),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER default 0,
  additional_information VARCHAR(4096)
) ;

create table oauth_code (
  code VARCHAR(256),
  authentication VARBINARY(MAX)
) ;

CREATE TABLE authz_approvals (
  username VARCHAR(36) not null,
  clientid VARCHAR(36) not null,
  scope VARCHAR(255) not null,
  expiresat DATETIME not null DEFAULT '2001-01-01 01:01:01.000001',
  status VARCHAR(50) default 'APPROVED' not null,
  lastmodifiedat DATETIME not null DEFAULT CURRENT_TIMESTAMP,
  primary key (username, clientid, scope)
) ;

CREATE TABLE groups (
  id VARCHAR(36) not null primary key,
  displayname VARCHAR(255) not null,
  created DATETIME default current_timestamp not null,
  lastmodified DATETIME null,
  version INTEGER default 0 not null,
  constraint unique_uk_2 unique(displayname)
) ;

CREATE TABLE group_membership (
  group_id VARCHAR(36) not null,
  member_id VARCHAR(36) not null,
  member_type VARCHAR(8) default 'USER' not null,
  authorities VARCHAR(255) default 'READ' not null,
  added DATETIME default current_timestamp not null,
  primary key (group_id, member_id)
) ;

CREATE TABLE external_group_mapping (
  group_id VARCHAR(36) not null,
  external_group VARCHAR(255) not null,
  added DATETIME default current_timestamp not null,
  primary key (group_id, external_group)
);

GO
CREATE TRIGGER set_authz_approvals_last_updated_at ON authz_approvals
AFTER UPDATE 
AS
BEGIN
  UPDATE authz_approvals
  SET lastmodifiedat = CURRENT_TIMESTAMP
  FROM Inserted i
  WHERE authz_approvals.username = i.username AND authz_approvals.clientid = i.clientid AND authz_approvals.scope=i.scope;
END
