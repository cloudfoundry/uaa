package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class UserInfoTableTest extends JdbcTestBase {

    private static List<TestColumn> TEST_COLUMNS = Arrays.asList(
            new TestColumn("user_id", "varchar", 36),
            new TestColumn("info", "longvarchar/mediumtext", 0)
    );

    @Override
    public void setUp() {
        MockEnvironment environment = new MockEnvironment();
        if (System.getProperty("spring.active.profiles") != null) {
            environment.setActiveProfiles(System.getProperty("spring.active.profiles"));
        }
        setUp(environment);
    }

    private static boolean testColumn(String name, String type, int size) {
        return testColumn(TEST_COLUMNS, name, type, size);
    }

    private static boolean testColumn(List<TestColumn> columns, String name, String type, int size) {
        for (TestColumn c : columns) {
            if (c.name.equalsIgnoreCase(name)) {
                final boolean contains = c.type.toLowerCase().contains(type.toLowerCase());
                return "varchar".equalsIgnoreCase(type) && !"info".equalsIgnoreCase(name) ?
                        contains && c.size == size : contains;
            }
        }
        return false;
    }

    @Test
    public void validate_table() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundTable = false;
            int foundColumn = 0;
            ResultSet rs = meta.getColumns(connection.getCatalog(), null, null, null);
            String tableName = "user_info";
            while (rs.next()) {
                String rstableName = rs.getString("TABLE_NAME");
                String rscolumnName = rs.getString("COLUMN_NAME");
                int columnSize = rs.getInt("COLUMN_SIZE");
                if (tableName.equalsIgnoreCase(rstableName)) {
                    assertTrue("Testing column:" + rscolumnName, testColumn(rscolumnName, rs.getString("TYPE_NAME"), columnSize));
                    foundTable = true;
                    foundColumn++;
                }
            }
            rs.close();
            assertTrue("Table " + tableName + " not found!", foundTable);
            assertEquals("Table " + tableName + " is missing columns!", TEST_COLUMNS.size(), foundColumn);

            rs = meta.getIndexInfo(connection.getCatalog(), null, tableName, false, false);
            if (!rs.next()) {
                rs = meta.getIndexInfo(connection.getCatalog(), null, tableName.toUpperCase(), false, false);
                assertTrue(rs.next());
            }
        }
    }

    public static class TestColumn {
        public final String name;
        public final String type;
        public final int size;

        TestColumn(String name, String type, int size) {
            this.name = name;
            this.type = type;
            this.size = size;
        }
    }

}
