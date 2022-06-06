package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.util.concurrent.atomic.AtomicInteger;

import org.cloudfoundry.identity.uaa.ratelimiting.core.RateLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdType;
import org.cloudfoundry.identity.uaa.ratelimiting.util.FileLoader;
import org.cloudfoundry.identity.uaa.ratelimiting.util.FileLoaderFileSystem;
import org.cloudfoundry.identity.uaa.ratelimiting.util.FileLoaderRestTemplate;
import org.cloudfoundry.identity.uaa.ratelimiting.util.Null;

import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfig.Fetcher;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfig.LoaderLogger;

public abstract class AbstractRateLimiterConfigConfiguration {
    protected final boolean rateLimiting;
    protected final String sourceReference;

    protected AbstractRateLimiterConfigConfiguration() {
        rateLimiting = RateLimiter.isEnabled();
        sourceReference = rateLimiting ? RateLimiter.configUrl() : null;
    }

    abstract protected LoaderLogger loaderLogger();

    protected RateLimitingConfigLoader createLoader( CredentialIdType... credentialIdTypes ) {
        if ( !rateLimiting ) {
            return null;
        }
        FileLoader loader = Null.errorOn( "fileLoader", fileLoader() );
        LoaderLogger logger = Null.defaultOn( loaderLogger(), DEFAULT_LOGGER );
        Fetcher fetcher = Null.errorOn( "fetcher", fetcher( loader, logger ) );
        return new RateLimitingConfigLoader( logger, fetcher, credentialIdTypes );
    }

    protected FileLoader fileLoader() {
        String filePrefix = RateLimiter.UrlPrefix.file.asPrefix(); // sourceReference must start with 'file://' or either 'https://' or 'http://'
        return sourceReference.startsWith( filePrefix ) ?
               new FileLoaderFileSystem( sourceReference ) :
               new FileLoaderRestTemplate( sourceReference );
    }

    protected Fetcher fetcher( FileLoader fileLoader, LoaderLogger logger ) {
        AtomicInteger loggingLimiter = new AtomicInteger( 0 );
        return () -> {
            int currentCallIndex = loggingLimiter.getAndIncrement(); // Called every 15 secs
            String yaml = fileLoader.load();
            if ( 0 == (currentCallIndex & 3) ) { // first call AND every 4th call (once a minute)
                logger.logFetchingFrom( sourceReference );
            }
            return yaml;
        };
    }

    private static final LoaderLogger DEFAULT_LOGGER = new LoaderLogger() {
        @Override
        public void logFetchingFrom( String source ) {
        }

        @Override
        public void logError( RateLimitingConfigException e ) {
        }

        @Override
        public void logUnhandledError( RuntimeException e ) {
        }

        @Override
        public void logUpdate( String msg ) {
        }
    };
}
