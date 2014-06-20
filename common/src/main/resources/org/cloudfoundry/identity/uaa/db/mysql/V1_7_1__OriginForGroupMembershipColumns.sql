-- column that holds the origin of the user, something like 'uaa' or 'ldap' or 'keystone'
ALTER TABLE group_membership ADD COLUMN origin varchar(36) default 'uaa' NOT NULL;
