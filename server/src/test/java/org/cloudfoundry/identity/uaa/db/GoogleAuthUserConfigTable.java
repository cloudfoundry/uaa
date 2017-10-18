package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.hamcrest.Matchers;
import org.junit.Test;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class GoogleAuthUserConfigTable extends JdbcTestBase{
    public String tableName = "user_google_mfa_credentials";

    private List<TestColumn> TEST_COLUMNS = Arrays.asList(
            new TestColumn("user_id", "varchar",  36),
            new TestColumn("secret_key","varchar", 255),
            new TestColumn("validation_code", "integer", -1),
            new TestColumn("scratch_codes", "varchar", 255));

    @Test
    public void validate_table() throws Exception {
        try(Connection connection = dataSource.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundTable = false;
            int foundColumn = 0;
            ResultSet rs = meta.getColumns(connection.getCatalog(), null, null, null);
            while (rs.next()) {
                String rstableName = rs.getString("TABLE_NAME");
                String rscolumnName = rs.getString("COLUMN_NAME");
                int actualColumnSize = rs.getInt("COLUMN_SIZE");
                if (tableName.equalsIgnoreCase(rstableName)) {
                    String actualColumnType = rs.getString("TYPE_NAME");
                    testColumn(rscolumnName, actualColumnType, actualColumnSize);
                    foundTable = true;
                    foundColumn++;
                }
            }
            rs.close();
            assertTrue("Table " + tableName + " not found!", foundTable);
            assertEquals("Table " + tableName + " is missing columns!", TEST_COLUMNS.size(), foundColumn);
        }
    }

    public void testColumn(String name, String actualType, int size) {
        testColumn(TEST_COLUMNS, name, actualType, size);
    }

    public void testColumn(List<TestColumn> columns, String name, String actualType, int size) {
        for (TestColumn c : columns) {
            if (c.name.equalsIgnoreCase(name)) {
                assertThat("Error for column: " + c.name, actualType.toLowerCase(), Matchers.containsString(c.type.toLowerCase()));
                if(c.size > 0) {
                    assertEquals("Error for column: " + c.name, c.size, size);
                }
            }
        }
    }

    public static class TestColumn {
        public final String name;
        public final String type;
        public final int size;

        public TestColumn(String name, String type, int size) {
            this.name = name;
            this.type = type;
            this.size = size;
        }
    }
}
