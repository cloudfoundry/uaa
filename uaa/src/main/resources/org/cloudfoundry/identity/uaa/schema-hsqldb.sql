-- Autogenerated: do not edit this file

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

CREATE TABLE SEC_AUDIT (
   principal_id char(36) not null,
   event_type INTEGER not null,
   origin VARCHAR(255) not null,
   event_data VARCHAR(255),
   created TIMESTAMP default current_timestamp
) ;
