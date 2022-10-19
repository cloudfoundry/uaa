package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.io.IOException;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;

public interface RateLimitingConfig {
    interface Fetcher {
        String fetchYaml()
                throws IOException;
    }

    interface ConfigLogger {
        void logError( RateLimitingConfigException e );

        void logUnhandledError( Exception e );
    }

    interface LoaderLogger extends ConfigLogger {
        void logFetchingFrom( String source );

        void logUpdate( String msg );

        default void logUpdate( int newFactoryCount ) {
            logUpdate( "RateLimitingConfig updated; new Factory count: " + newFactoryCount );
        }
    }
}
