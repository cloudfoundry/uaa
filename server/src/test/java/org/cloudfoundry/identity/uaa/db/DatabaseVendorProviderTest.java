package org.cloudfoundry.identity.uaa.db;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.sql.DataSource;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

class DatabaseVendorProviderTest {

    private DatabaseVendorProvider provider;

    private JdbcTemplate jdbcTemplate;
    private DatabaseMetaData dbMetaData;

    @BeforeEach
    public void setUp() throws Exception {
        provider = new DatabaseVendorProvider();

        jdbcTemplate = mock(JdbcTemplate.class);
        DataSource dataSource = mock(DataSource.class);
        Connection connection = mock(Connection.class);
        dbMetaData = mock(DatabaseMetaData.class);
        when(jdbcTemplate.getDataSource()).thenReturn(dataSource);
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.getMetaData()).thenReturn(dbMetaData);
    }

    @Test
    void testPostgreSQLVendor() throws SQLException {
        when(dbMetaData.getDatabaseProductName()).thenReturn("PostgreSQL");
        Vendor databaseVendor = provider.getDatabaseVendor(jdbcTemplate);
        assertEquals(Vendor.postgresql, databaseVendor);
    }

    @Test
    void mySQLVendor() throws SQLException {
        when(dbMetaData.getDatabaseProductName()).thenReturn("MySQL DB");
        Vendor databaseVendor = provider.getDatabaseVendor(jdbcTemplate);
        assertEquals(Vendor.mysql, databaseVendor);
    }

    @Test
    void hsqldbVendor() throws SQLException {
        when(dbMetaData.getDatabaseProductName()).thenReturn("HSQL Database Engine");
        Vendor databaseVendor = provider.getDatabaseVendor(jdbcTemplate);
        assertEquals(Vendor.hsqldb, databaseVendor);
    }

    @Test
    void otherVendor() throws SQLException {
        when(dbMetaData.getDatabaseProductName()).thenReturn("Other DB");
        Vendor databaseVendor = provider.getDatabaseVendor(jdbcTemplate);
        assertEquals(Vendor.unknown, databaseVendor);
    }
}
