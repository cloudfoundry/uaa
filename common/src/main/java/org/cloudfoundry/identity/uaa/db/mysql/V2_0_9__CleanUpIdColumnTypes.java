package org.cloudfoundry.identity.uaa.db.mysql;

import java.sql.Connection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.jdbc.datasource.init.ScriptException;

import com.googlecode.flyway.core.api.migration.jdbc.JdbcMigration;

public class V2_0_9__CleanUpIdColumnTypes implements JdbcMigration {
    private static final Log logger = LogFactory.getLog(V2_0_9__CleanUpIdColumnTypes.class);
    @Override
    public void migrate(Connection connection) throws Exception {
        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        populator.addScript(new ClassPathResource(V2_0_9__CleanUpIdColumnTypes.class.getName().replace('.', '/')+".txt"));
        populator.setIgnoreFailedDrops(true);
        try {
            populator.populate(connection);
        } catch (ScriptException ex) {
            logger.warn("validation failed for cleanup of UUID column data types, proceeding with startup", ex);
        }
    }

}
