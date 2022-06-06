package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.io.IOException;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;

public interface RateLimitingConfig {
    interface Fetcher {
        String fetchYaml()
                throws IOException;
    }

    interface LoaderLogger {
        void logFetchingFrom( String source );

        void logError( RateLimitingConfigException e );

        void logUnhandledError( RuntimeException e );

        void logUpdate( String msg );

        default void logUpdate( int newFactoryCount ) {
            logUpdate( "RateLimitingConfig updated; new Factory count: " + newFactoryCount );
        }
    }
}
