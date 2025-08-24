package org.cloudfoundry.identity.uaa.util.beans;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.MetaDataAccessException;

import java.sql.DatabaseMetaData;
import java.sql.SQLException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DbUtilsTest {
    private static final String IDENTIFIER_NAME = "XYZ";
    private static final String BACKTICK = "`";
    private static final String DOUBLE_QUOTE = "\"";
    private static final String SINGLE_QUOTE = "'";

    private final DbUtils.MetaDataExtractor metaDataExtractor = mock(DbUtils.MetaDataExtractor.class);
    private final DbUtils dbUtils = new DbUtils(metaDataExtractor);
    private final DatabaseMetaData databaseMetaData = mock(DatabaseMetaData.class);
    private final JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);

    @BeforeEach
    void setup() throws MetaDataAccessException {
        when(metaDataExtractor.extractDatabaseMetaData(any())).thenReturn(databaseMetaData);
    }

    @Test
    void canQuoteHsqldbIdentifiers() throws SQLException {
        when(databaseMetaData.getURL()).thenReturn("jdbc:hsqldb:mem:uaa");

        String quotedIdentifier = dbUtils.getQuotedIdentifier(IDENTIFIER_NAME, jdbcTemplate);
        assertThat(quotedIdentifier).isEqualTo(IDENTIFIER_NAME);
    }

    @Test
    void canCacheForHsqldb() throws SQLException {
        when(databaseMetaData.getURL())
                .thenReturn("jdbc:hsqldb:mem:uaa", "SHOULD NOT SEE THIS");
        dbUtils.getQuotedIdentifier(IDENTIFIER_NAME, jdbcTemplate);

        String subsequentQuotedIdentifier = dbUtils.getQuotedIdentifier(IDENTIFIER_NAME, jdbcTemplate);
        assertThat(subsequentQuotedIdentifier).isEqualTo(IDENTIFIER_NAME);
    }

    @Nested
    @DisplayName("Tests for databases other than HSQLDB")
    class nonHsqldbTests {
        @BeforeEach
        void setup() throws SQLException {
            when(databaseMetaData.getURL())
                    .thenReturn("Anything but the h-s-q-l-d-b");
        }

        @Test
        void canQuoteWithBackticks_ForMysql() throws SQLException {
            when(databaseMetaData.getIdentifierQuoteString()).thenReturn(BACKTICK);

            String quotedIdentifier = dbUtils.getQuotedIdentifier(IDENTIFIER_NAME, jdbcTemplate);
            assertThat(quotedIdentifier).isEqualTo(BACKTICK + IDENTIFIER_NAME + BACKTICK);
        }

        @Test
        void canQuoteWithDoubleQuote_ForPostgres() throws SQLException {
            when(databaseMetaData.getIdentifierQuoteString()).thenReturn(DOUBLE_QUOTE);

            String quotedIdentifier = dbUtils.getQuotedIdentifier(IDENTIFIER_NAME, jdbcTemplate);
            assertThat(quotedIdentifier).isEqualTo(DOUBLE_QUOTE + IDENTIFIER_NAME + DOUBLE_QUOTE);
        }

        @Test
        void canCache() throws SQLException {
            when(databaseMetaData.getIdentifierQuoteString()).thenReturn(BACKTICK, DOUBLE_QUOTE);
            dbUtils.getQuotedIdentifier(IDENTIFIER_NAME, jdbcTemplate);

            String subsequentQuotedIdentifier = dbUtils.getQuotedIdentifier(IDENTIFIER_NAME, jdbcTemplate);
            assertThat(subsequentQuotedIdentifier).isEqualTo(BACKTICK + IDENTIFIER_NAME + BACKTICK);
        }

        @ParameterizedTest
        @ValueSource(strings = {SINGLE_QUOTE, "", BACKTICK + DOUBLE_QUOTE})
        @NullSource
        void rejectsInvalidQuoteStrings(String quoteString) throws SQLException {
            when(databaseMetaData.getIdentifierQuoteString()).thenReturn(quoteString);
            assertThatExceptionOfType(Throwable.class).isThrownBy(() -> dbUtils.getQuotedIdentifier(IDENTIFIER_NAME, jdbcTemplate));
        }

        @Test
        void abortsWhenCannotGetMetaData() throws MetaDataAccessException {
            when(metaDataExtractor.extractDatabaseMetaData(any())).thenThrow(MetaDataAccessException.class);
            assertThatExceptionOfType(RuntimeException.class).isThrownBy(() -> dbUtils.getQuotedIdentifier(IDENTIFIER_NAME, jdbcTemplate));
        }
    }
}
