--
-- Copyright (c) [2016] Cloud Foundry Foundation. All Rights Reserved.
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
   username NVARCHAR(255) not null,
   password NVARCHAR(255) not null,
   email NVARCHAR(255) not null,
   authority BIGINT DEFAULT 0 not null,
   givenname NVARCHAR(255),
   familyname NVARCHAR(255),
   active BIT DEFAULT 1 not null,
   phonenumber NVARCHAR(255),
   authorities NVARCHAR(1024) DEFAULT 'uaa.user',
   verified BIT DEFAULT 0 NOT NULL
);

CREATE UNIQUE INDEX unique_uk_1 on users (username);

CREATE TABLE sec_audit (
   principal_id char(36) not null,
   event_type INTEGER not null,
   origin NVARCHAR(255) not null,
   event_data NVARCHAR(255),
   created DATETIME default current_timestamp
) ;

CREATE TABLE oauth_client_details (
  client_id NVARCHAR(255) PRIMARY KEY,
  resource_ids NVARCHAR(1024),
  client_secret NVARCHAR(256),
  scope NVARCHAR(255),
  authorized_grant_types NVARCHAR(255),
  web_server_redirect_uri NVARCHAR(1024),
  authorities NVARCHAR(255),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER default 0,
  additional_information NVARCHAR(4000)
) ;

create table oauth_code (
  code NVARCHAR(256),
  authentication VARBINARY(MAX)
) ;

CREATE TABLE authz_approvals (
  username NVARCHAR(36) not null,
  clientid NVARCHAR(36) not null,
  scope NVARCHAR(255) not null,
  expiresat DATETIME not null DEFAULT '2001-01-01 01:01:01.000001',
  status NVARCHAR(50) default 'APPROVED' not null,
  lastmodifiedat DATETIME not null DEFAULT CURRENT_TIMESTAMP,
  primary key (username, clientid, scope)
) ;

CREATE TABLE groups (
  id NVARCHAR(36) not null primary key,
  displayname NVARCHAR(255) not null,
  created DATETIME default current_timestamp not null,
  lastmodified DATETIME null,
  version INTEGER default 0 not null,
  constraint unique_uk_2 unique(displayname)
) ;

CREATE TABLE group_membership (
  group_id NVARCHAR(36) not null,
  member_id NVARCHAR(36) not null,
  member_type NVARCHAR(8) default 'USER' not null,
  authorities NVARCHAR(255) default 'READ' not null,
  added DATETIME default current_timestamp not null,
  primary key (group_id, member_id)
) ;

CREATE TABLE external_group_mapping (
  group_id NVARCHAR(36) not null,
  external_group NVARCHAR(255) not null,
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
