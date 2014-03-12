package org.cloudfoundry.identity.uaa.test;

import javax.sql.DataSource;

import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class HsqldbHelper {
    public static void truncateSchema(DataSource datasource) throws SQLException {
        new JdbcTemplate(datasource).execute("TRUNCATE SCHEMA public AND COMMIT");
    }
}
