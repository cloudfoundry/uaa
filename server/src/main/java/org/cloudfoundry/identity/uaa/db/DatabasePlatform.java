package org.cloudfoundry.identity.uaa.db;


import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;

/**
 * Encodes the defaults for a given database platform.
 */
public enum DatabasePlatform {

    POSTGRESQL("postgresql", "select 1", ChronoUnit.SECONDS),
    MYSQL("mysql", "select 1", ChronoUnit.MILLIS),
    HSQLDB("hsqldb", "select 1 from information_schema.system_users", ChronoUnit.SECONDS);

    public final String type;
    public final String validationQuery;
    public final TemporalUnit timeoutUnit;

    DatabasePlatform(String type, String validationQuery, TemporalUnit timeoutUnit) {
        this.type = type;
        this.validationQuery = validationQuery;
        this.timeoutUnit = timeoutUnit;
    }

    /**
     * The connectTimeout property is platform-specific. In Postgres, it is expressed
     * in seconds. In MySQL, it is expressed in milliseconds. HSQL is in-memory and
     * does not need a connect timeout, but it is not incorrect to pass one.
     *
     * @param timeout the required timeout
     * @return the numeric value to be used in a JDBC url.
     */
    public long getJdbcUrlTimeoutValue(Duration timeout) {
        if (this.timeoutUnit.equals(ChronoUnit.MILLIS)) {
            return timeout.toMillis();
        }
        return timeout.toSeconds();
    }
}
