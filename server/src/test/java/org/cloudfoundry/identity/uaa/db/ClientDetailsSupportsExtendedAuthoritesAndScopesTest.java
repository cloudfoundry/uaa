package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

@WithDatabaseContext
class ClientDetailsSupportsExtendedAuthoritesAndScopesTest {
    @Autowired
    private DataSource dataSource;

    private String tableName = "oauth_client_details";
    private String scopeColumnName = "scope";
    private String authoritiesColumnName = "authorities";

    @Test
    void authoritiesAndScopesAreExtended() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundTable = false;
            boolean foundColumnScope = false;
            boolean foundColumnAuthorities = false;
            ResultSet rs = meta.getColumns(connection.getCatalog(), null, null, null);
            while (rs.next()) {
                String rstableName = rs.getString("TABLE_NAME");
                String rscolumnName = rs.getString("COLUMN_NAME");
                int columnSize = rs.getInt("COLUMN_SIZE");
                if (tableName.equalsIgnoreCase(rstableName) && (scopeColumnName.equalsIgnoreCase(rscolumnName)
                        || authoritiesColumnName.equalsIgnoreCase(rscolumnName))) {
                    assertThat(columnSize).as("Table: %s Column: %s should be over 4000 chars".formatted(rstableName, rscolumnName)).isGreaterThan(4000);
                    foundTable = true;
                    if (scopeColumnName.equalsIgnoreCase(rscolumnName)) {
                        foundColumnScope = true;
                    } else if (authoritiesColumnName.equalsIgnoreCase(rscolumnName)) {
                        foundColumnAuthorities = true;
                    }

                    String columnType = rs.getString("TYPE_NAME");
                    assertThat("Table: %s Column: %s should have a column type".formatted(rstableName, rscolumnName)).as(columnType).isNotNull();
                    assertThat(columnType.toLowerCase()).as("Table: %s Column: %s should be text, longtext, nvarchar or clob".formatted(rstableName, rscolumnName)).isIn(Arrays.asList("text", "longtext", "nvarchar", "clob"));
                }
            }
            rs.close();

            assertThat(foundTable).as("I was expecting to find table:" + tableName).isTrue();
            assertThat(foundColumnScope).as("I was expecting to find column: " + scopeColumnName).isTrue();
            assertThat(foundColumnAuthorities).as("I was expecting to find column: " + authoritiesColumnName).isTrue();
        }
    }
}
