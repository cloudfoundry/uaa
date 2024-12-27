package org.cloudfoundry.identity.uaa.db;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.lookup.DataSourceLookupFailureException;

import java.sql.Connection;
import java.sql.SQLException;

public interface MigrationTest {
    String getTargetMigration();

    void runAssertions() throws Exception;

    static String getDatabaseCatalog(JdbcTemplate jdbcTemplate) {
        try (Connection connection = jdbcTemplate.getDataSource().getConnection()) {
            return  connection.getCatalog();
        } catch (SQLException e) {
            throw new DataSourceLookupFailureException("Unable to look up database schema.", e);
        }
    }
}