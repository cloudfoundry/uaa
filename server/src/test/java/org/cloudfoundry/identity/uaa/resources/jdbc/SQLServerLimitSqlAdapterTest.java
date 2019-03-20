package org.cloudfoundry.identity.uaa.resources.jdbc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalToIgnoringCase;
import static org.hamcrest.Matchers.is;

class SQLServerLimitSqlAdapterTest {

    private SQLServerLimitSqlAdapter sqlServerLimitAdapter;

    @BeforeEach
    void setUp() {
        sqlServerLimitAdapter = new SQLServerLimitSqlAdapter();
    }

    static class SqlServerLimitArgumentsProvider implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of("select * from table1 order by column_name", 1, 1,
                            "select * from table1 order by column_name OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY;"),
                    Arguments.of("select * from table1 order by column_name", 5, 1,
                            "select * from table1 order by column_name OFFSET 5 ROWS FETCH NEXT 1 ROWS ONLY;"),
                    Arguments.of("select * from table1 order by column_name", 1, 5,
                            "select * from table1 order by column_name OFFSET 1 ROWS FETCH NEXT 5 ROWS ONLY;"),
                    Arguments.of("select * from table1 order by column_name asc", 1, 1,
                            "select * from table1 order by column_name asc OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY;"),
                    Arguments.of("select * from table1 order by column_name desc", 1, 1,
                            "select * from table1 order by column_name desc OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY;"),
                    Arguments.of("select * from table1", 1, 1,
                            "select * from table1 ORDER BY 1 OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY;")
            );
        }
    }

    @ParameterizedTest
    @ArgumentsSource(SqlServerLimitArgumentsProvider.class)
    void testSQLServerLimit(String inputSql, int index, int size, String expectedSql) {
        String generatedSql = sqlServerLimitAdapter.getLimitSql(inputSql, index, size);
        assertThat(generatedSql, is(equalToIgnoringCase(expectedSql)));
    }
}