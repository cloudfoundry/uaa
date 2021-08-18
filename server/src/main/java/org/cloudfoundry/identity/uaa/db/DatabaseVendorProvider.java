package org.cloudfoundry.identity.uaa.db;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

public class DatabaseVendorProvider {

    private static Logger logger = LoggerFactory.getLogger(DatabaseVendorProvider.class);

    public Vendor getDatabaseVendor(JdbcTemplate jdbcTemplate) {
        if (jdbcTemplate != null && jdbcTemplate.getDataSource() != null) {
            try (Connection con = jdbcTemplate.getDataSource().getConnection()) {
                DatabaseMetaData metaData = con.getMetaData();
                String databaseProductName = metaData.getDatabaseProductName();
                if ("PostgreSQL".equals(databaseProductName)) {
                    return Vendor.postgresql;
                } else if (databaseProductName.startsWith("HSQL")) {
                    return Vendor.hsqldb;
                } else if (databaseProductName.startsWith("MySQL")) {
                    return Vendor.mysql;
                }
            } catch (SQLException e) {
                logger.warn("Could not determine Type of Database, returning default.");
            }
        }
        return Vendor.unknown; //Could not determine Vendor type, fall back to generic SQL
    }
}
