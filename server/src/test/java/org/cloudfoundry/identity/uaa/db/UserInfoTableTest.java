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

import static org.assertj.core.api.Assertions.assertThat;

@WithDatabaseContext
class UserInfoTableTest {

    private static List<TestColumn> testColumns = Arrays.asList(
            new TestColumn("user_id", "varchar", 36),
            new TestColumn("info", "longvarchar/mediumtext", 0)
    );

    private static boolean testColumn(String name, String type, int size) {
        return testColumn(testColumns, name, type, size);
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
    void validate_table(
            @Autowired DataSource dataSource
    ) throws Exception {
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
                    assertThat(testColumn(rscolumnName, rs.getString("TYPE_NAME"), columnSize)).as("Testing column:" + rscolumnName).isTrue();
                    foundTable = true;
                    foundColumn++;
                }
            }
            rs.close();
            assertThat(foundTable).as("Table " + tableName + " not found!").isTrue();
            assertThat(foundColumn).as("Table " + tableName + " is missing columns!").isEqualTo(testColumns.size());

            rs = meta.getIndexInfo(connection.getCatalog(), null, tableName, false, false);
            if (!rs.next()) {
                rs = meta.getIndexInfo(connection.getCatalog(), null, tableName.toUpperCase(), false, false);
                assertThat(rs.next()).isTrue();
            }
        }
    }

}
