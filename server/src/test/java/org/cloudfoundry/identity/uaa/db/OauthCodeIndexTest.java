package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.springframework.beans.factory.annotation.Autowired;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@WithDatabaseContext
class OauthCodeIndexTest {

    @Autowired
    private DataSource dataSource;

    static class ExistingIndiciesProvider implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of("oauth_code", "oauth_code_uq_idx", true),
                    Arguments.of("oauth_code", "oauth_code_expiresat_idx", false)
            );
        }
    }

    @ParameterizedTest
    @ArgumentsSource(ExistingIndiciesProvider.class)
    void existingIndicies(
            final String uncasedTableName,
            final String indexName,
            final boolean unique
    ) throws Exception {
        boolean found = false;
        for (String tableName : Arrays.asList(uncasedTableName.toLowerCase(), uncasedTableName.toUpperCase())) {
            try (
                    Connection connection = dataSource.getConnection();
                    ResultSet rs = connection.getMetaData().getIndexInfo(connection.getCatalog(), null, tableName, unique, true)
            ) {
                while (!found && rs.next()) {
                    found = indexName.equalsIgnoreCase(rs.getString("INDEX_NAME"));
                }
            }
            if (found) {
                break;
            }
        }

        assertThat(found).as("Expected to find index %s.%s".formatted(uncasedTableName, indexName)).isTrue();
    }

}
