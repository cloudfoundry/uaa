package org.cloudfoundry.identity.uaa.ratelimiting.core.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;

import lombok.ToString;

@ToString
public class LimiterMapping {
    private final String name;
    private final RequestsPerWindowSecs withCallerCredentialsID;
    private final RequestsPerWindowSecs withCallerRemoteAddressID;
    private final RequestsPerWindowSecs withoutCallerID;
    private final RequestsPerWindowSecs global;
    private final List<PathSelector> pathSelectors;

    public LimiterMapping(String name,
            String withCallerCredentialsID, String withCallerRemoteAddressID, String withoutCallerID,
            String global, List<String> pathSelectors) {
        this.name = StringUtils.stripToNull(name);
        this.global = RequestsPerWindowSecs.from(name, "global", global); // ...from() can throw Exceptions
        this.withCallerCredentialsID = RequestsPerWindowSecs.from(name, "withCallerCredentialsID", withCallerCredentialsID);
        this.withCallerRemoteAddressID = RequestsPerWindowSecs.from(name, "withCallerRemoteAddressID", withCallerRemoteAddressID);
        this.withoutCallerID = RequestsPerWindowSecs.from(name, "withoutCallerID", withoutCallerID);
        this.pathSelectors = PathSelector.listFrom(name, pathSelectors); // can throw Exceptions

        if ((withCallerCredentialsID() == null) && (withCallerRemoteAddressID() == null)
                && (withoutCallerID() == null) && (global() == null)) {
            throw new RateLimitingConfigException( "No limits (" +
                    "'withCallerCredentialsID', 'withCallerRemoteAddressID', 'withoutCallerID', " +
                    "or 'global') from Rate Limiting configuration with name: " + name );
        }
    }

    /**
     * Name / type for the LimiterFactories,
     * can be anything (including <code>null</code>) but
     * must be unique within the current set of Limiter Factories.
     * <p>
     * Note: Leading and Trailing white space is removed and an empty string
     * is treated as <code>null</code>.
     * <p>
     * Note: paths are mapped to this name / type, and are the
     * primary mechanism to support different limits per endpoint / path.
     */
    public String name() {
        return this.name;
    }

    public RequestsPerWindowSecs withCallerCredentialsID() {
        return this.withCallerCredentialsID;
    }

    public RequestsPerWindowSecs withCallerRemoteAddressID() {
        return this.withCallerRemoteAddressID;
    }

    public RequestsPerWindowSecs withoutCallerID() {
        return this.withoutCallerID;
    }

    public RequestsPerWindowSecs global() {
        return this.global;
    }

    public List<PathSelector> pathSelectors() {
        return this.pathSelectors;
    }

    public int limitsCount() {
        return ObjectUtils.countNonNull(withCallerCredentialsID, withCallerRemoteAddressID, withoutCallerID, global);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String name;
        private String withCallerCredentialsID;
        private String withCallerRemoteAddressID;
        private String withoutCallerID;
        private String global;
        private final List<String> pathSelectors = new ArrayList<>();

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder withCallerCredentialsID(String withCallerCredentialsID) {
            this.withCallerCredentialsID = withCallerCredentialsID;
            return this;
        }

        public Builder withCallerRemoteAddressID(String withCallerRemoteAddressID) {
            this.withCallerRemoteAddressID = withCallerRemoteAddressID;
            return this;
        }

        public Builder withoutCallerID(String withoutCallerID) {
            this.withoutCallerID = withoutCallerID;
            return this;
        }

        public Builder global(String global) {
            this.global = global;
            return this;
        }

        public Builder pathSelectors(String... pathSelectors) {
            return pathSelectors(Arrays.asList(pathSelectors));
        }

        public Builder pathSelectors(List<String> pathSelectors) {
            this.pathSelectors.addAll(pathSelectors);
            return this;
        }

        public Builder pathSelector(String pathSelector) {
            this.pathSelectors.add(pathSelector);
            return this;
        }

        public LimiterMapping build() {
            return new LimiterMapping( name, withCallerCredentialsID, withCallerRemoteAddressID, withoutCallerID, global,
                    pathSelectors );
        }
    }
}
