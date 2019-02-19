alter table oauth_code add column id serial;
alter table external_group_mapping add column id serial;
alter table sec_audit add column id serial;
alter table group_membership add column id serial;

alter table oauth_code add primary key (id);
alter table external_group_mapping add primary key (id);
alter table sec_audit add primary key (id);
alter table group_membership add primary key (id);
