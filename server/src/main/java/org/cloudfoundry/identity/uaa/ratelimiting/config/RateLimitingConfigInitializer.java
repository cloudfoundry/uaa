package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdType;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking.LimiterManagerImpl;

public class RateLimitingConfigInitializer {

    public RateLimitingConfigInitializer(boolean rateLimiting, LoaderLogger logger, CredentialIdType... credentialIdTypes) {
        if ( !rateLimiting ) {
            return;
        }

        InitialConfig initialConfig = InitialConfig.SINGLETON.getInstance();
        Exception initialError = initialConfig.getInitialError();
        YamlConfigFileDTO localConfigDTO = initialConfig.getLocalConfigFileDTO();
        RateLimitingFactoriesSupplierWithStatus configurationWithStatus = initialConfig.getConfigurationWithStatus();

        LimiterManagerImpl limiterManager = LimiterManagerImpl.SINGLETON.getInstance();

        if ( initialError instanceof RateLimitingConfigException) {
            logger.logError( (RateLimitingConfigException)initialError );
        } else if ( initialError != null ) {
            logger.logUnhandledError( initialError );
        }

        RateLimitingConfigMapper configMapper = new RateLimitingConfigMapperImpl( credentialIdTypes );
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
    }
}
