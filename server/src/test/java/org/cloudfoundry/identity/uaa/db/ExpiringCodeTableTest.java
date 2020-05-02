package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@WithDatabaseContext
class ExpiringCodeTableTest {

    private static List<TestColumn> TEST_COLUMNS = Arrays.asList(
            new TestColumn("code", "varchar/nvarchar", 255),
            new TestColumn("expiresat", "bigint/int8", -1),
            new TestColumn("data", "longtext/mediumtext/nvarchar", -1),
            new TestColumn("intent", "longtext/mediumtext/nvarchar", -1),
            new TestColumn("identity_zone_id", "varchar/nvarchar", 36)
    );

    private static boolean testColumn(String name, String type, int size) {
        return testColumn(TEST_COLUMNS, name, type, size);
    }

    private static boolean testColumn(List<TestColumn> columns, String name, String type, int size) {
        for (TestColumn c : columns) {
            if (c.name.equalsIgnoreCase(name)) {
                return c.type.toLowerCase().contains(type.toLowerCase()) && c.size > 0 ? c.size == size : true;
            }
        }
        return false;
    }

    @Test
    void validate_table(@Autowired DataSource dataSource) throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundTable = false;
            int foundColumn = 0;
            ResultSet rs = meta.getColumns(connection.getCatalog(), null, null, null);
            String tableName = "expiring_code_store";
            while (rs.next()) {
                String rstableName = rs.getString("TABLE_NAME");
                String rscolumnName = rs.getString("COLUMN_NAME");
                int actualColumnSize = rs.getInt("COLUMN_SIZE");
                if (tableName.equalsIgnoreCase(rstableName)) {
                    String actualColumnType = rs.getString("TYPE_NAME");
                    assertTrue("Testing column:" + rscolumnName, testColumn(rscolumnName, actualColumnType, actualColumnSize));
                    foundTable = true;
                    foundColumn++;
                }
            }
            rs.close();
            assertTrue("Table " + tableName + " not found!", foundTable);
            assertEquals("Table " + tableName + " is missing columns!", TEST_COLUMNS.size(), foundColumn);
        }
    }

}
