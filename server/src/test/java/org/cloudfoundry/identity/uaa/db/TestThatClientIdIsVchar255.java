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

import static org.assertj.core.api.Assertions.assertThat;

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

    @ParameterizedTest
    @ArgumentsSource(ClientIdArgumentsProvider.class)
    void that_client_id_is_varchar_255(
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

                    assertThat(columnSize).as("Table:" + rstableName + " Column:" + rscolumnName + " should be 255 in size.").isEqualTo(255);
                    foundTable = true;
                    foundColumn = true;
                    String columnType = rs.getString("TYPE_NAME");
                    assertThat(columnType).as("Table:" + rstableName + " Column:" + rscolumnName + " should have a column type.").isNotNull();
                    assertThat(columnType.toLowerCase()).as("Table:" + rstableName + " Column:" + rscolumnName + " should be varchar").isEqualTo("varchar");

                }
            }
            rs.close();

            final String springProfile = String.join(", ", configurableEnvironment.getActiveProfiles());
            assertThat(foundTable).as("[" + springProfile + "] I was expecting to find table:" + tableName).isTrue();
            assertThat(foundColumn).as("[" + springProfile + "] I was expecting to find column: client_id").isTrue();
        }
    }
}
