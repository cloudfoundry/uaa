This folder contains an interactive schema explorer for the MySQL schema. Start at [index.html](index.html). To generate these:

1. Run uaa with the mysql profile to generate the database locally.
2. Run the following sql script to add foreign key constraints. These are only for the purposes of showing relationships in the diagrams.

  ```sql
ALTER TABLE authz_approvals ADD FOREIGN KEY (user_id) REFERENCES users (id);
ALTER TABLE authz_approvals ADD FOREIGN KEY (client_id) REFERENCES oauth_client_details (client_id);
ALTER TABLE client_idp ADD FOREIGN KEY (client_id) REFERENCES oauth_client_details (client_id);
ALTER TABLE client_idp ADD FOREIGN KEY (identity_provider_id) REFERENCES identity_provider (id);
ALTER TABLE external_group_mapping ADD FOREIGN KEY (group_id) REFERENCES groups (id);
ALTER TABLE group_membership ADD FOREIGN KEY (group_id) REFERENCES groups (id);
ALTER TABLE group_membership ADD FOREIGN KEY (identity_provider_id) REFERENCES identity_provider (id);
ALTER TABLE identity_provider ADD FOREIGN KEY (identity_zone_id) REFERENCES identity_zone (id);
ALTER TABLE oauth_client_details ADD FOREIGN KEY (identity_zone_id) REFERENCES identity_zone (id);
ALTER TABLE users ADD FOREIGN KEY (identity_provider_id) REFERENCES identity_provider (id);
  ```
3. Install [Graphviz](http://www.graphviz.org/Download..php)
4. Download [The MySQL JDBC Driver](http://search.maven.org/remotecontent?filepath=mysql/mysql-connector-java/5.1.34/mysql-connector-java-5.1.34.jar)
5. Download [SchemaSpy](http://downloads.sourceforge.net/project/schemaspy/schemaspy/SchemaSpy%205.0.0/schemaSpy_5.0.0.jar?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fschemaspy%2Ffiles%2Fschemaspy%2F&ts=1415373348&use_mirror=superb-dca2)
6. Run the following in this directory:

  ```sh
java -jar ~/Downloads/schemaSpy_5.0.0.jar -t mysql -db uaa -host localhost \
-u root -o . -dp ~/Downloads/mysql-connector-java-5.1.34.jar -noads -noimplied
  ```
