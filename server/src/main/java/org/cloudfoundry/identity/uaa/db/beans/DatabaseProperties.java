package org.cloudfoundry.identity.uaa.db.beans;


import lombok.Getter;
import lombok.Setter;
import org.cloudfoundry.identity.uaa.db.DatabasePlatform;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;

import java.util.Arrays;

/**
 * Represents the configurable properties for the database, set either through
 * end-user config, or through profiles.
 * <p>
 * Casing is inconsistent but required by legacy configuration property names.
 */
@ConfigurationProperties(prefix = "database")
@Getter
@Setter
public class DatabaseProperties implements EnvironmentAware {

    private String driverClassName;
    private String username;
    private String password;
    private String url;
    private int maxParameters;
    private boolean useSkipLocked;
    private boolean caseinsensitive;
    // This is not intended to be exposed in the configuration, but is useful for tests
    private String defaultUrl;

    // With defaults
    private DatabasePlatform platform = DatabasePlatform.HSQLDB;
    private Integer connecttimeout = 10;
    private long validationinterval = 5000;
    private boolean testwhileidle = false;
    private int minidle = 0;
    private int maxidle = 10;
    private int maxactive = 100;
    private int maxwait = 30_000;
    private int initialsize = 10;
    private int validationquerytimeout = 10;
    private boolean removedAbandoned = false;
    private boolean logabandoned = true;
    private int abandonedtimeout = 300;
    private int evictionintervalms = 15_000;
    private int minevictionidlems = 60_000;

    public String getUrl() {
        return this.url != null ? this.url : this.defaultUrl;
    }

    public String getValidationQuery() {
        return this.platform.validationQuery;
    }

    public DatabasePlatform getDatabasePlatform() {
        return this.platform;
    }

    @Override
    public void setEnvironment(Environment environment) {
        var profiles = Arrays.asList(environment.getActiveProfiles());

        if (profiles.contains("postgresql")) {
            this.platform = DatabasePlatform.POSTGRESQL;
        } else if (profiles.contains("mysql")) {
            this.platform = DatabasePlatform.MYSQL;
        } else {
            this.platform = DatabasePlatform.HSQLDB;
        }
    }

}
