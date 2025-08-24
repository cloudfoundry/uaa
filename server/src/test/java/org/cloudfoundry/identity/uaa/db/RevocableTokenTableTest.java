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
class RevocableTokenTableTest {

    private List<TestColumn> testColumns = Arrays.asList(
            new TestColumn("token_id", "varchar/nvarchar", 36),
            new TestColumn("client_id", "varchar/nvarchar", 255),
            new TestColumn("user_id", "varchar/nvarchar", 36),
            new TestColumn("format", "varchar/nvarchar", 255),
            new TestColumn("response_type", "varchar/nvarchar", 25),
            new TestColumn("issued_at", "bigint/int8", 64),
            new TestColumn("expires_at", "bigint/int8", 64),
            new TestColumn("scope", "text/longtext/nvarchar/clob", 0),
            new TestColumn("data", "nvarchar/longvarchar/mediumtext", 0),
            new TestColumn("identity_zone_id", "varchar/nvarchar", 36)
    );

    private List<TestColumn> testIndex = Arrays.asList(
            new TestColumn("idx_revocable_token_client_id", "", 0),
            new TestColumn("idx_revocable_token_user_id", "", 0),
            new TestColumn("idx_revocable_token_expires_at", "", 0)

    );

    public boolean testColumn(String name, String type, int size) {
        return testColumn(testColumns, name, type, size);
    }

    public boolean testColumn(List<TestColumn> columns, String name, String type, int size) {
        for (TestColumn c : columns) {
            if (c.name.equalsIgnoreCase(name)) {
                return ("varchar".equalsIgnoreCase(type) || "nvarchar".equalsIgnoreCase(type)) && !("data".equalsIgnoreCase(name) || "scope".equalsIgnoreCase(name)) ?
                        c.type.toLowerCase().contains(type.toLowerCase()) && c.size == size :
                        c.type.toLowerCase().contains(type.toLowerCase());
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
            String tableName = "revocable_tokens";
            while (rs.next()) {
                String rstableName = rs.getString("TABLE_NAME");
                String rscolumnName = rs.getString("COLUMN_NAME");
                int actualColumnSize = rs.getInt("COLUMN_SIZE");
                if (tableName.equalsIgnoreCase(rstableName)) {
                    String actualColumnType = rs.getString("TYPE_NAME");
                    assertThat(testColumn(rscolumnName, actualColumnType, actualColumnSize)).as("Testing column:" + rscolumnName).isTrue();
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
            int indexCount = 0;
            do {
                String indexName = rs.getString("INDEX_NAME");
                short indexType = rs.getShort("TYPE");
                if (shouldCompareIndex(indexName)) {
                    assertThat(testColumn(testIndex, indexName, "", indexType)).as("Testing index: " + indexName).isTrue();
                    indexCount++;

                }
            } while (rs.next());
            assertThat(indexCount).as("One or more indices are missing").isEqualTo(testIndex.size());
        }
    }

    boolean shouldCompareIndex(String indexName) {
        for (TestColumn c : testIndex) {
            if (c.name.equalsIgnoreCase(indexName)) {
                return true;
            }
        }
        return false;
    }

}
