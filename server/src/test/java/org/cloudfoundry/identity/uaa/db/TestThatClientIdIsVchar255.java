package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.ConfigurableEnvironment;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithDatabaseContext
class TestThatClientIdIsVchar255 {

    @Autowired
    private ConfigurableEnvironment configurableEnvironment;

    @Autowired
    private DataSource dataSource;

    static class ClientIdArgumentsProvider implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of("authz_approvals", "client_id"),
                    Arguments.of("oauth_client_details", "client_id"),
                    Arguments.of("sec_audit", "principal_id")
            );
        }
    }

//    @Parameterized.Parameters(name = "{index}: org.cloudfoundry.identity.uaa.db[{0}]; table[{1}]")
//    public static Collection<Object[]> data() {
//        return Arrays.asList(new Object[][]{
//                {null, "authz_approvals", "client_id"},
//                {null, "oauth_client_details", "client_id"},
//                {null, "sec_audit", "principal_id"},
////            {"hsqldb", "authz_approvals", "client_id"},
////            {"hsqldb", "oauth_client_details", "client_id"},
////            {"hsqldb", "sec_audit", "principal_id"},
////            {"postgresql", "authz_approvals", "client_id"},
////            {"postgresql", "oauth_client_details", "client_id"},
////            {"postgresql", "sec_audit", "principal_id"},
////            {"mysql", "authz_approvals", "client_id"},
////            {"mysql", "oauth_client_details", "client_id"},
////            {"mysql", "sec_audit", "principal_id"},
//        });
//    }

    @ParameterizedTest
    @ArgumentsSource(ClientIdArgumentsProvider.class)
    void test_That_ClientId_Is_Varchar_255(
            final String tableName,
            final String columnName
    ) throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundTable = false;
            boolean foundColumn = false;
            ResultSet rs = meta.getColumns(connection.getCatalog(), null, null, null);
            while ((!foundTable) && rs.next()) {
                String rstableName = rs.getString("TABLE_NAME");
                String rscolumnName = rs.getString("COLUMN_NAME");
                int columnSize = rs.getInt("COLUMN_SIZE");
                if (tableName.equalsIgnoreCase(rstableName) && columnName.equalsIgnoreCase(rscolumnName)) {

                    assertEquals(255, columnSize, "Table:" + rstableName + " Column:" + rscolumnName + " should be 255 in size.");
                    foundTable = true;
                    foundColumn = true;
                    String columnType = rs.getString("TYPE_NAME");
                    assertNotNull(columnType, "Table:" + rstableName + " Column:" + rscolumnName + " should have a column type.");
                    assertEquals("varchar", columnType.toLowerCase(), "Table:" + rstableName + " Column:" + rscolumnName + " should be varchar");

                }
            }
            rs.close();

            final String springProfile = String.join(", ", configurableEnvironment.getActiveProfiles());
            assertTrue(foundTable, "[" + springProfile + "] I was expecting to find table:" + tableName);
            assertTrue(foundColumn, "[" + springProfile + "] I was expecting to find column: client_id");
        }
    }
}
