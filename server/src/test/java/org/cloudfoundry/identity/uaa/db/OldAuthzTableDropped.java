package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;

import static org.junit.Assert.assertFalse;

public class OldAuthzTableDropped extends JdbcTestBase {

    @Override
    public void setUp() {
        MockEnvironment environment = new MockEnvironment();
        if (System.getProperty("spring.active.profiles") != null) {
            environment.setActiveProfiles(System.getProperty("spring.active.profiles"));
        }
        setUp(environment);
    }

    @Test
    public void validate_table() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundTable = false;
            ResultSet rs = meta.getTables(connection.getCatalog(), null, null, null);
            String tableName = "authz_approvals_old";
            while (rs.next() && !foundTable) {
                foundTable = (tableName.equalsIgnoreCase(rs.getString("TABLE_NAME")));
            }
            rs.close();
            assertFalse("Table " + tableName + " found!", foundTable);
        }
    }
}
