package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.util.concurrent.atomic.AtomicInteger;

import org.cloudfoundry.identity.uaa.ratelimiting.core.RateLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdType;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking.LimiterManagerImpl;
import org.cloudfoundry.identity.uaa.ratelimiting.util.FileLoader;
import org.cloudfoundry.identity.uaa.ratelimiting.util.FileLoaderRestTemplate;
import org.cloudfoundry.identity.uaa.ratelimiting.util.Null;

import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfig.Fetcher;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfig.LoaderLogger;

public abstract class AbstractRateLimiterConfigConfiguration {
    protected final boolean rateLimiting;

    protected AbstractRateLimiterConfigConfiguration() {
        rateLimiting = RateLimiter.isEnabled();
    }

    abstract protected LoaderLogger loaderLogger();

    protected RateLimitingConfigLoader createLoader( CredentialIdType... credentialIdTypes ) {
        if ( !rateLimiting ) {
            return null;
        }
        LoaderLogger logger = Null.defaultOn( loaderLogger(), DEFAULT_LOGGER );

        InitialConfig initialConfig = InitialConfig.SINGLETON.getInstance();
        Exception initialError = initialConfig.getInitialError();
        String dynamicUpdateURL = initialConfig.getDynamicUpdateURL();
        YamlConfigFileDTO localConfigDTO = initialConfig.getLocalResourceConfigFileDTO();
        RateLimitingFactoriesSupplierWithStatus configurationWithStatus = initialConfig.getConfigurationWithStatus();
        boolean updatingEnabled = dynamicUpdateURL != null; // only !null if specified w/ http:// or https://

        LimiterManagerImpl limiterManager = LimiterManagerImpl.SINGLETON.getInstance();

        limiterManager.update( configurationWithStatus );

        if ( initialError instanceof RateLimitingConfigException ) {
            logger.logError( (RateLimitingConfigException)initialError );
        } else if ( initialError != null ) {
            logger.logUnhandledError( initialError );
        }

        RateLimitingConfigMapper configMapper = new RateLimitingConfigMapperImpl( updatingEnabled, credentialIdTypes );
        if ( localConfigDTO != null ) {
            String source = "Local Config File";
            logger.logFetchingFrom( source );
            configurationWithStatus = configMapper.map( configurationWithStatus, source, localConfigDTO );
            limiterManager.update( configurationWithStatus );
            logger.logUpdate( configurationWithStatus.getStatusJson() );
        }

        Fetcher fetcher = null;
        if ( updatingEnabled ) {
            FileLoader loader = Null.errorOn( "fileLoader", fileLoader( dynamicUpdateURL ) );
            fetcher = Null.errorOn( "fetcher", fetcher( loader, logger, dynamicUpdateURL ) );
        }
        return new RateLimitingConfigLoader( logger, fetcher, dynamicUpdateURL, configMapper, configurationWithStatus );
    }

    protected FileLoader fileLoader( String dynamicUpdateURL ) {
        return new FileLoaderRestTemplate( dynamicUpdateURL );
    }

    protected Fetcher fetcher( FileLoader fileLoader, LoaderLogger logger, String dynamicUpdateURL ) {
        AtomicInteger loggingLimiter = new AtomicInteger( 0 );
        return () -> {
            int currentCallIndex = loggingLimiter.getAndIncrement(); // Called every 15 secs
            String yaml = fileLoader.load();
            if ( 0 == (currentCallIndex & 3) ) { // first call AND every 4th call (once a minute)
                logger.logFetchingFrom( dynamicUpdateURL );
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
        public void logUnhandledError( Exception e ) {
        }

        @Override
        public void logUpdate( String msg ) {
        }
    };
}
