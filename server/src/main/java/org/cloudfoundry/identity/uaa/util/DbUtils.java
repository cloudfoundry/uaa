package org.cloudfoundry.identity.uaa.util;

import org.hsqldb.persist.HsqlDatabaseProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.JdbcUtils;
import org.springframework.jdbc.support.MetaDataAccessException;

import java.sql.DatabaseMetaData;
import java.sql.SQLException;

public abstract class DbUtils {
    private static final Logger s_logger = LoggerFactory.getLogger(DbUtils.class);

    public static String getQuotedIdentifier(String identifier, JdbcTemplate jdbcTemplate)
            throws SQLException {
        DatabaseMetaData metaData;
        try {
            metaData = JdbcUtils.extractDatabaseMetaData(
                    jdbcTemplate.getDataSource(), dbmd -> dbmd);
        }
        catch (MetaDataAccessException ex) {
            if (s_logger.isWarnEnabled()) {
                s_logger.warn("Failed to extract DatabaseMetaData, returning the original identifier - "
                        + identifier, ex);
            }
            // Of course, this will be wrong for mysql8, causing errors when the
            // identifier is used in SQL statements later
            return identifier;
        }

        if (HsqlDatabaseProperties.PRODUCT_NAME.equals(metaData.getDatabaseProductName())) {
            // HSQL's databasemetadata's getIdentifierQuoteString returns double quotes, which is incorrect
            // So we override with the value that actually works with HSQL db
            return identifier;
        }
        else {
            final String identifierQuoteString = metaData.getIdentifierQuoteString();
            return identifierQuoteString + identifier + identifierQuoteString;
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

