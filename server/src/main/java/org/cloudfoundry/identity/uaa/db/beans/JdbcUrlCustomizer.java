package org.cloudfoundry.identity.uaa.db.beans;


/**
 * Utility type, allows users to provide beans to customize the JDBC url.
 */
@FunctionalInterface
public interface JdbcUrlCustomizer {

    String customize(String url);
}
