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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithDatabaseContext
class GoogleAuthUserConfigTableTest {
    String tableName = "user_google_mfa_credentials";

    private List<TestColumn> TEST_COLUMNS = Arrays.asList(
            new TestColumn("user_id", "nvarchar/varchar", 36),
            new TestColumn("secret_key", "nvarchar/varchar", 255),
            new TestColumn("encryption_key_label", "nvarchar/varchar", 255),
            new TestColumn("encrypted_validation_code", "nvarchar/varchar", 255),
            new TestColumn("validation_code", "integer/int4/int", -1),
            new TestColumn("scratch_codes", "nvarchar/varchar", 255),
            new TestColumn("mfa_provider_id", "char/character/bpchar", 36),
            new TestColumn("zone_id", "char/character/bpchar", 36));

    @Test
    void validate_table(@Autowired DataSource dataSource) throws Exception {
        try (Connection connection = dataSource.getConnection()) {
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
            assertTrue(foundTable, "Table " + tableName + " not found!");
            assertEquals(TEST_COLUMNS.size(), foundColumn, "Table " + tableName + " is missing columns!");
        }
    }

    void testColumn(String name, String actualType, int size) {
        testColumn(TEST_COLUMNS, name, actualType, size);
    }

    void testColumn(List<TestColumn> columns, String name, String actualType, int size) {
        for (TestColumn c : columns) {
            if (c.name.equalsIgnoreCase(name)) {
                assertTrue(c.type.toLowerCase().contains(actualType.toLowerCase()), "Error for column: " + c.name + " was type " + actualType.toLowerCase());
                if (c.size > 0) {
                    assertEquals(c.size, size, "Error for column: " + c.name);
                }
            }
        }
    }
}
