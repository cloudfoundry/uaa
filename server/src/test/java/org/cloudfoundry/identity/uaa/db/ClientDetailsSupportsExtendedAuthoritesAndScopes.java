package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.isIn;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithDatabaseContext
class ClientDetailsSupportsExtendedAuthoritesAndScopes {

    private String tableName = "oauth_client_details";
    private String scopeColumnName = "scope";
    private String authoritiesColumnName = "authorities";

    @Test
    void authoritiesAndScopesAreExtended(@Autowired DataSource dataSource) throws Exception {
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
                    assertTrue(columnSize > 4000, String.format("Table: %s Column: %s should be over 4000 chars", rstableName, rscolumnName));
                    foundTable = true;
                    if (scopeColumnName.equalsIgnoreCase(rscolumnName)) {
                        foundColumnScope = true;
                    } else if (authoritiesColumnName.equalsIgnoreCase(rscolumnName)) {
                        foundColumnAuthorities = true;
                    }

                    String columnType = rs.getString("TYPE_NAME");
                    assertNotNull(String.format("Table: %s Column: %s should have a column type", rstableName, rscolumnName), columnType);
                    assertThat(String.format("Table: %s Column: %s should be text, longtext, nvarchar or clob", rstableName, rscolumnName), columnType.toLowerCase(), isIn(Arrays.asList("text", "longtext", "nvarchar", "clob")));
                }
            }
            rs.close();

            assertTrue(foundTable, "I was expecting to find table:" + tableName);
            assertTrue(foundColumnScope, "I was expecting to find column: " + scopeColumnName);
            assertTrue(foundColumnAuthorities, "I was expecting to find column: " + authoritiesColumnName);
        }
    }
}
