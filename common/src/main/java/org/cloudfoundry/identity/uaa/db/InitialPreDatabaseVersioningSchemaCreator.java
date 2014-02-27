package org.cloudfoundry.identity.uaa.db;

import com.googlecode.flyway.core.api.migration.jdbc.JdbcMigration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import java.sql.Connection;

/**
 * Created by pivotal on 2/13/14.
 *
 * This file is in place to allow FlywayDB to advance the database version to 1.5.3.
 * This file, invoked by its descendants, will automatically apply the script
 * V1_5_2__initial_db.sql in order to create a database the way UAA used to behave.
 * This file exists for the pure sake that it will work on existing UAA databases, as well
 * as brand new databases.
 *
 */
public class InitialPreDatabaseVersioningSchemaCreator implements JdbcMigration {

    private String type;

    public InitialPreDatabaseVersioningSchemaCreator(String type) {
        this.type = type;
    }

    @Override
    public void migrate(Connection connection) throws Exception {
        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        populator.addScript(new ClassPathResource("org/cloudfoundry/identity/uaa/db/"+type+"/V1_5_2__initial_db.sql"));
        populator.setContinueOnError(true);
        populator.setIgnoreFailedDrops(true);
        populator.populate(connection);
    }
}
