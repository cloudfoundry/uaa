package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdType;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.LimiterFactorySupplierUpdatable;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking.LimiterManagerImpl;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RateLimitingConfigInitializerTest {

    @Test
    void noRateLimit() {
        //Check rateLImiting false does not require any parameters
        RateLimitingConfigInitializer rateLimitingConfigInitializer = new RateLimitingConfigInitializer(false, null, null, null);
        assertThat(rateLimitingConfigInitializer).isNotNull();
    }

    @Test
    void checkInitialConfig() {
        LoaderLogger logger = mock(LoaderLogger.class);
        InitialConfig initialConfig = mock(InitialConfig.class);
        YamlConfigFileDTO configFileDto = mock(YamlConfigFileDTO.class);
        when(initialConfig.getLocalConfigFileDTO()).thenReturn(configFileDto);
        RateLimitingFactoriesSupplierWithStatus configWithStatus = mock(RateLimitingFactoriesSupplierWithStatus.class);
        RateLimiterStatus status = mock(RateLimiterStatus.class);
        when(status.getFromSource()).thenReturn("source");
        when(configWithStatus.getStatus()).thenReturn(status);
        when(initialConfig.getConfigurationWithStatus()).thenReturn(configWithStatus);
        LimiterManagerImpl limiterManager = mock(LimiterManagerImpl.class);
        CredentialIdType credentialType = mock(CredentialIdType.class);

        new RateLimitingConfigInitializer(true, logger, initialConfig, limiterManager, credentialType);

        verify(limiterManager).update(any(RateLimitingFactoriesSupplierWithStatus.class));
        verify(logger).logUpdate(anyString());
        verify(limiterManager).startBackgroundProcessing();
    }

    @Test
    void checkInitialConfig_logsError() {
        LoaderLogger logger = mock(LoaderLogger.class);
        InitialConfig initialConfig = mock(InitialConfig.class);
        RateLimitingConfigException exception = mock(RateLimitingConfigException.class);
        when(initialConfig.getInitialError()).thenReturn(exception);
        LimiterManagerImpl limiterManager = mock(LimiterManagerImpl.class);

        new RateLimitingConfigInitializer(true, logger, initialConfig, limiterManager);

        verify(logger).logError(exception);
        verify(limiterManager, times(0)).update(any(RateLimitingFactoriesSupplierWithStatus.class));
        verify(logger, times(0)).logUpdate(anyString());
    }

    @Test
    void checkInitialConfig_logsUnhandledError() {
        LoaderLogger logger = mock(LoaderLogger.class);
        InitialConfig initialConfig = mock(InitialConfig.class);
        YamlConfigFileDTO configFileDto = mock(YamlConfigFileDTO.class);
        when(initialConfig.getLocalConfigFileDTO()).thenReturn(configFileDto);
        Exception exception = mock(Exception.class);
        when(initialConfig.getInitialError()).thenReturn(exception);
        RateLimitingFactoriesSupplierWithStatus configWithStatus = mock(RateLimitingFactoriesSupplierWithStatus.class);
        when(initialConfig.getConfigurationWithStatus()).thenReturn(configWithStatus);
        LimiterManagerImpl limiterManager = mock(LimiterManagerImpl.class);
        CredentialIdType credentialType = mock(CredentialIdType.class);

        new RateLimitingConfigInitializer(true, logger, initialConfig, limiterManager, credentialType);

        verify(logger).logUnhandledError(exception);
        verify(limiterManager).update(any(RateLimitingFactoriesSupplierWithStatus.class));
        verify(logger).logUpdate(anyString());
    }

    @Test
    void checkPredestroyStopsBackgroundProcessing() {
        LimiterFactorySupplierUpdatable limiterManager = mock(LimiterFactorySupplierUpdatable.class);
        LoaderLogger logger = mock(LoaderLogger.class);
        InitialConfig initialConfig = mock(InitialConfig.class);
        RateLimitingFactoriesSupplierWithStatus configWithStatus = mock(RateLimitingFactoriesSupplierWithStatus.class);
        when(initialConfig.getConfigurationWithStatus()).thenReturn(configWithStatus);
        RateLimiterStatus status = mock(RateLimiterStatus.class);
        when(configWithStatus.getStatus()).thenReturn(status);

        RateLimitingConfigInitializer configInitializer = new RateLimitingConfigInitializer(true, logger, initialConfig, limiterManager);

        verify(limiterManager).startBackgroundProcessing();
        verify(limiterManager, times(0)).shutdownBackgroundProcessing();

        configInitializer.predestroy();

        verify(limiterManager).shutdownBackgroundProcessing();
    }
}
