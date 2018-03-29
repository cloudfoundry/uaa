alter table oauth_code add column id integer;
alter table external_group_mapping add column id integer;
alter table sec_audit add column id integer;
alter table group_membership add column id integer;

alter table oauth_code add primary key (id);
alter table external_group_mapping add primary key (id);
alter table sec_audit add primary key (id);
alter table group_membership add primary key (id);
