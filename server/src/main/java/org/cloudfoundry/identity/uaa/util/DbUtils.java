package org.cloudfoundry.identity.uaa.util;

import com.google.common.annotations.VisibleForTesting;
import org.hsqldb.persist.HsqlDatabaseProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.JdbcUtils;
import org.springframework.jdbc.support.MetaDataAccessException;

import javax.sql.DataSource;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;

public class DbUtils {
    private static final Logger s_logger = LoggerFactory.getLogger(DbUtils.class);
    private static final DbUtils instance = new DbUtils();
    private static final char BACKTICK = '`';
    private static final char DOUBLE_QUOTE = '"';
    private static final char MYSQL_IDENTIFIER_QUOTE = BACKTICK;
    private static final char POSTGRES_IDENTIFIER_QUOTE = DOUBLE_QUOTE;

    private final MetaDataExtractor metaDataExtractor;

    interface MetaDataExtractor {
        DatabaseMetaData extractDatabaseMetaData(DataSource dataSource)
                throws MetaDataAccessException;
    }

    private DbUtils() {
        this.metaDataExtractor = dataSource -> JdbcUtils.extractDatabaseMetaData(dataSource, x -> x);
    }

    @VisibleForTesting
    DbUtils(MetaDataExtractor metaDataExtractor) {
        this.metaDataExtractor = metaDataExtractor;
    }

    public static DbUtils getInstance() {
        return instance;
    }

    public String getQuotedIdentifier(String identifier, JdbcTemplate jdbcTemplate)
            throws SQLException {

        DatabaseMetaData metaData;
        try {
            metaData = metaDataExtractor.extractDatabaseMetaData(
                    jdbcTemplate.getDataSource()
            );
        } catch (MetaDataAccessException ex) {
            s_logger.error("Failed to extract DatabaseMetaData, aborting");
            throw new RuntimeException("Failed to extract DatabaseMetaData", ex);
        }

        if (HsqlDatabaseProperties.PRODUCT_NAME.equals(metaData.getDatabaseProductName())) {
            // HSQL's databasemetadata's getIdentifierQuoteString returns double quotes, which is incorrect
            // So we override with the value that actually works with HSQL db
            return identifier;
        } else {
            char quoteChar = getIdentifierQuoteChar(metaData);
            return String.format("%c%s%c", quoteChar, identifier, quoteChar);
        }
    }

    private static char getIdentifierQuoteChar(DatabaseMetaData metaData) throws SQLException {
        final String identifierQuoteString = metaData.getIdentifierQuoteString();
        if (identifierQuoteString == null || identifierQuoteString.length() != 1) {
            throw new RuntimeException("Unexpected database identifier quote string: '" + identifierQuoteString + "'");
        }
        char quoteChar = identifierQuoteString.charAt(0);

        // Whitelist the allowable strings to protect against SQL injection
        if (quoteChar == MYSQL_IDENTIFIER_QUOTE || quoteChar == POSTGRES_IDENTIFIER_QUOTE) {
            return quoteChar;
        } else {
            throw new RuntimeException("Unexpected database identifier quote character: '" + quoteChar + "'");
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

