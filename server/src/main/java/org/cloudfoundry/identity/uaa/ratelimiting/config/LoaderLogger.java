package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;

public interface LoaderLogger {
    void logError(RateLimitingConfigException e);

    void logUnhandledError(Exception e);

    void logFetchingFrom( String source );

    void logUpdate( String msg );
}
