package org.cloudfoundry.identity.uaa.util.beans;

import org.cloudfoundry.identity.uaa.error.UaaDBException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.JdbcUtils;
import org.springframework.jdbc.support.MetaDataAccessException;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.util.Optional;

@Component
public class DbUtils {
    private static final Logger s_logger = LoggerFactory.getLogger(DbUtils.class);
    private static final char BACKTICK = '`';
    private static final char DOUBLE_QUOTE = '"';
    private static final char MYSQL_IDENTIFIER_QUOTE = BACKTICK;
    private static final char POSTGRES_IDENTIFIER_QUOTE = DOUBLE_QUOTE;

    private final MetaDataExtractor metaDataExtractor;
    private Optional<QuoteCharacter> cachedQuoteCharacter = Optional.empty();

    interface MetaDataExtractor {
        DatabaseMetaData extractDatabaseMetaData(DataSource dataSource)
                throws MetaDataAccessException;
    }

    public DbUtils() {
        this.metaDataExtractor = dataSource -> JdbcUtils.extractDatabaseMetaData(dataSource, x -> x);
    }

    DbUtils(MetaDataExtractor metaDataExtractor) {
        this.metaDataExtractor = metaDataExtractor;
    }

    private enum QuoteCharacter {
        NONE,
        DOUBLE_QUOTE,
        BACKTICK;

        static QuoteCharacter valueOf(char character) {
            switch (character) {
                case DbUtils.DOUBLE_QUOTE:
                    return DOUBLE_QUOTE;
                case DbUtils.BACKTICK:
                    return BACKTICK;
                default:
                    throw new UaaDBException("Unexpected database identifier quote character: '" + character + "'");
            }
        }
    }

    public synchronized String getQuotedIdentifier(String identifier, JdbcTemplate jdbcTemplate)
            throws SQLException {

        if (cachedQuoteCharacter.isPresent()) {
            switch (cachedQuoteCharacter.get()) {
                case DOUBLE_QUOTE:
                    return "%c%s%c".formatted(DOUBLE_QUOTE, identifier, DOUBLE_QUOTE);
                case BACKTICK:
                    return "%c%s%c".formatted(BACKTICK, identifier, BACKTICK);
                case NONE:
                    return identifier;
                default:
                    throw new UaaDBException("Unexpected enum value:" + cachedQuoteCharacter.get());
            }
        } else {
            QuoteCharacter quoteCharacter = computeQuoteCharacter(jdbcTemplate);
            cachedQuoteCharacter = Optional.of(quoteCharacter);
            return getQuotedIdentifier(identifier, jdbcTemplate);
        }
    }

    private QuoteCharacter computeQuoteCharacter(JdbcTemplate jdbcTemplate) throws SQLException {
        try {
            var metaData = metaDataExtractor.extractDatabaseMetaData(jdbcTemplate.getDataSource());
            if (metaData.getURL().startsWith("jdbc:hsqldb:")) {
                // HSQL's databasemetadata's getIdentifierQuoteString returns double quotes, which is incorrect
                // So we override with the value that actually works with HSQL db
                return QuoteCharacter.NONE;
            }
            return QuoteCharacter.valueOf(getIdentifierQuoteChar(metaData));
        } catch (MetaDataAccessException ex) {
            s_logger.error("Failed to extract DatabaseMetaData, aborting");
            throw new UaaDBException("Failed to extract DatabaseMetaData", ex);
        }
    }

    private static char getIdentifierQuoteChar(DatabaseMetaData metaData) throws SQLException {
        final String identifierQuoteString = metaData.getIdentifierQuoteString();
        if (identifierQuoteString == null || identifierQuoteString.length() != 1) {
            throw new UaaDBException("Unexpected database identifier quote string: '" + identifierQuoteString + "'");
        }
        char quoteChar = identifierQuoteString.charAt(0);

        // Whitelist the allowable strings to protect against SQL injection
        if (quoteChar == MYSQL_IDENTIFIER_QUOTE || quoteChar == POSTGRES_IDENTIFIER_QUOTE) {
            return quoteChar;
        } else {
            throw new UaaDBException("Unexpected database identifier quote character: '" + quoteChar + "'");
        }
    }

    public static int getDatabaseMajorVersion(JdbcTemplate jdbcTemplate)
            throws SQLException, MetaDataAccessException {
        try {
            return JdbcUtils.extractDatabaseMetaData(
                    jdbcTemplate.getDataSource(), dbmd -> dbmd).getDatabaseMajorVersion();
        } catch (MetaDataAccessException ex) {
            s_logger.error("Failed to extract database major version");
            throw ex;
        }
    }
}
