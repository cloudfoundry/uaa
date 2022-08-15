package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.cloudfoundry.identity.uaa.ratelimiting.core.RateLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdType;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking.LimiterManagerImpl;
import org.cloudfoundry.identity.uaa.ratelimiting.util.FileLoader;
import org.cloudfoundry.identity.uaa.ratelimiting.util.FileLoaderRestTemplate;

import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfig.Fetcher;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfig.LoaderLogger;

public abstract class AbstractRateLimiterConfigConfiguration {
    protected final boolean rateLimiting;

    protected AbstractRateLimiterConfigConfiguration() {
        rateLimiting = RateLimiter.isEnabled();
    }

    protected abstract LoaderLogger loaderLogger();

    protected RateLimitingConfigLoader createLoader( CredentialIdType... credentialIdTypes ) {
        if ( !rateLimiting ) {
            return null;
        }
        LoaderLogger logger = Optional.ofNullable(loaderLogger()).orElse(DEFAULT_LOGGER);

        InitialConfig initialConfig = InitialConfig.SINGLETON.getInstance();
        Exception initialError = initialConfig.getInitialError();
        String dynamicUpdateURL = initialConfig.getDynamicUpdateURL();
        YamlConfigFileDTO localConfigDTO = initialConfig.getLocalConfigFileDTO();
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
            RateLimiterStatus status = configurationWithStatus.getStatus();
            String source = "Local Config File";
            if ((status != null) && (status.getFromSource() != null) ) {
                source = status.getFromSource();
            }
            logger.logFetchingFrom( source );
            configurationWithStatus = configMapper.map( configurationWithStatus, source, localConfigDTO );
            limiterManager.update( configurationWithStatus );
            logger.logUpdate( configurationWithStatus.getStatusJson() );
        }

        Fetcher fetcher = null;
        if ( updatingEnabled ) {
            FileLoader loader = Optional.ofNullable(fileLoader( dynamicUpdateURL )).orElseThrow(() -> new Error("No 'fileLoader' provided -- coding error"));
            fetcher = Optional.ofNullable(fetcher( loader, logger, dynamicUpdateURL )).orElseThrow(() -> new Error("No 'fetcher' provided -- coding error"));
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
            //Fallback instance, no logging implemented
        }

        @Override
        public void logError( RateLimitingConfigException e ) {
            //Fallback instance, no logging implemented
        }

        @Override
        public void logUnhandledError( Exception e ) {
            //Fallback instance, no logging implemented
        }

        @Override
        public void logUpdate( String msg ) {
            //Fallback instance, no logging implemented
        }
    };
}
