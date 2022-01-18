package org.cloudfoundry.identity.uaa.util;

import org.hsqldb.persist.HsqlDatabaseProperties;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.MetaDataAccessException;

import java.sql.DatabaseMetaData;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
    void setup() throws MetaDataAccessException, SQLException {
        when(metaDataExtractor.extractDatabaseMetaData(any())).thenReturn(databaseMetaData);
    }

    @Test
    void getInstanceGetsSingleton() {
        DbUtils instance1 = DbUtils.getInstance();
        DbUtils instance2 = DbUtils.getInstance();

        assertNotNull(instance1);
        assertEquals(instance1, instance2);
    }

    @Test
    void canQuoteHsqldbIdentifiers() throws SQLException {
        when(databaseMetaData.getDatabaseProductName()).thenReturn(HsqlDatabaseProperties.PRODUCT_NAME);

        String quotedIdentifier = dbUtils.getQuotedIdentifier(IDENTIFIER_NAME, jdbcTemplate);

        assertEquals(IDENTIFIER_NAME, quotedIdentifier);
    }

    @Nested
    @DisplayName("Tests for databases other than HSQLDB")
    class nonHsqldbTests {
        @BeforeEach
        void setup() throws MetaDataAccessException, SQLException {
            when(databaseMetaData.getDatabaseProductName())
                    .thenReturn("Anything but" + HsqlDatabaseProperties.PRODUCT_NAME);
        }

        @Test
        void canQuoteWithBackticks_ForMysql() throws SQLException {
            when(databaseMetaData.getIdentifierQuoteString()).thenReturn(BACKTICK);

            String quotedIdentifier = dbUtils.getQuotedIdentifier(IDENTIFIER_NAME, jdbcTemplate);

            assertEquals(BACKTICK + IDENTIFIER_NAME + BACKTICK, quotedIdentifier);
        }

        @Test
        void canQuoteWithDoubleQuote_ForPostgres() throws SQLException {
            when(databaseMetaData.getIdentifierQuoteString()).thenReturn(DOUBLE_QUOTE);

            String quotedIdentifier = dbUtils.getQuotedIdentifier(IDENTIFIER_NAME, jdbcTemplate);

            assertEquals(DOUBLE_QUOTE + IDENTIFIER_NAME + DOUBLE_QUOTE, quotedIdentifier);
        }

        @ParameterizedTest
        @ValueSource(strings = {SINGLE_QUOTE, "", BACKTICK + DOUBLE_QUOTE})
        @NullSource
        void rejectsInvalidQuoteStrings(String quoteString) throws SQLException {
            when(databaseMetaData.getIdentifierQuoteString()).thenReturn(quoteString);

            Assertions.assertThrows(Throwable.class, () -> {
                dbUtils.getQuotedIdentifier(IDENTIFIER_NAME, jdbcTemplate);
            });
        }

        @Test
        void abortsWhenCannotGetMetaData() throws MetaDataAccessException {
            when(metaDataExtractor.extractDatabaseMetaData(any())).thenThrow(MetaDataAccessException.class);

            Assertions.assertThrows(RuntimeException.class, () -> {
                dbUtils.getQuotedIdentifier(IDENTIFIER_NAME, jdbcTemplate);
            });
        }
    }
}
