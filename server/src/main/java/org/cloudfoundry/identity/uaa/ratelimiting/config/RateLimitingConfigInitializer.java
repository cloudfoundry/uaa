package org.cloudfoundry.identity.uaa.ratelimiting.config;

import jakarta.annotation.PreDestroy;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdType;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.LimiterFactorySupplierUpdatable;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;

public class RateLimitingConfigInitializer {

    LimiterFactorySupplierUpdatable limiterManager;

    public RateLimitingConfigInitializer(boolean rateLimiting, LoaderLogger logger, InitialConfig initialConfig, LimiterFactorySupplierUpdatable limiterManager, CredentialIdType... credentialIdTypes) {
        if (!rateLimiting) {
            return;
        }

        Exception initialError = initialConfig.getInitialError();
        YamlConfigFileDTO localConfigDTO = initialConfig.getLocalConfigFileDTO();
        RateLimitingFactoriesSupplierWithStatus configurationWithStatus = initialConfig.getConfigurationWithStatus();

        if (initialError instanceof RateLimitingConfigException exception) {
            logger.logError(exception);
        } else if (initialError != null) {
            logger.logUnhandledError(initialError);
        }

        this.limiterManager = limiterManager;
        this.limiterManager.startBackgroundProcessing();

        RateLimitingConfigMapper configMapper = new RateLimitingConfigMapperImpl( credentialIdTypes );
        if (localConfigDTO != null) {
            RateLimiterStatus status = configurationWithStatus.getStatus();
            String source = "Local Config File";
            if ((status != null) && (status.getFromSource() != null)) {
                source = status.getFromSource();
            }
            configurationWithStatus = configMapper.map(configurationWithStatus, source, localConfigDTO);
            limiterManager.update(configurationWithStatus);
            logger.logUpdate(configurationWithStatus.getStatusJson());
        }
    }


    @PreDestroy
    void predestroy() {
        if (this.limiterManager != null) {
            limiterManager.shutdownBackgroundProcessing();
        }
    }
}
