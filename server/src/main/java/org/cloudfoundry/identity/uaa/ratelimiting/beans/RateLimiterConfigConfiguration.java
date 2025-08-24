package org.cloudfoundry.identity.uaa.ratelimiting.beans;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.ratelimiting.config.InitialConfig;
import org.cloudfoundry.identity.uaa.ratelimiting.config.LoaderLogger;
import org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfigInitializer;
import org.cloudfoundry.identity.uaa.ratelimiting.core.RateLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.AuthorizationCredentialIdExtractorErrorLogger;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWTjsonField;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking.LimiterManagerImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring based configuration to configure the RateLimitingConfigLoader
 * <p>
 * Note: some messy-bits in the super class
 * <p>
 * Example Source Reference:
 * <a href="https://raw.githubusercontent.com/litesoft/RateLimiterExampleConfig/main/RateLimiters.yaml">https://raw.githubusercontent.com/litesoft/RateLimiterExampleConfig/main/RateLimiters.yaml</a> (url)
 */
@Configuration
public class RateLimiterConfigConfiguration {
    private final Log logger = LogFactory.getLog(RateLimiterConfigConfiguration.class);

    protected final boolean rateLimiting;

    protected RateLimiterConfigConfiguration() {
        rateLimiting = RateLimiter.isEnabled();
    }

    private static final LoaderLogger DEFAULT_LOGGER = new LoaderLogger() {

        @Override
        public void logError(RateLimitingConfigException e) {
            //Fallback instance, no logging implemented
        }

        @Override
        public void logUnhandledError(Exception e) {
            //Fallback instance, no logging implemented
        }

        @Override
        public void logUpdate(String msg) {
            //Fallback instance, no logging implemented
        }
    };

    @Bean
    public RateLimitingConfigInitializer loader() {
        AuthorizationCredentialIdExtractorErrorLogger errLogger =
                e -> logger.error("AuthorizationCredentialIdExtractor", e);
        return new RateLimitingConfigInitializer(rateLimiting, Optional.ofNullable(loaderLogger()).orElse(DEFAULT_LOGGER), InitialConfig.SINGLETON.getInstance(), LimiterManagerImpl.SINGLETON.getInstance(), new CredentialIdTypeJWT( errLogger ), new CredentialIdTypeJWTjsonField( errLogger ));
    }

    protected LoaderLogger loaderLogger() {
        AtomicReference<String> sourceReference = new AtomicReference<>();
        logger.info("RateLimiting initializing (wd: " + System.getProperty("user.dir"));
        return new LoaderLogger() {

            @Override
            public void logError(RateLimitingConfigException e) {
                logger.error(messageWith("", e), e);
            }

            @Override
            public void logUnhandledError(Exception e) {
                logger.error(messageWith(" (unhandled)", e), e);
            }

            @Override
            public void logUpdate(String msg) {
                logger.info(msg);
            }

            private String messageWith(String typePLus, Exception e) {
                StringBuilder sb = new StringBuilder();
                sb.append(RateLimiterConfigConfiguration.class.getSimpleName()).append(typePLus).append(": ");
                String eMessage = e == null ? "-No Exception-" : Optional.ofNullable(e.getMessage()).orElse("-No Message-");
                String reference = Optional.ofNullable(sourceReference.get()).orElse("-No sourceReference-");
                if (!eMessage.contains(reference)) {
                    sb.append(reference).append(" | ");
                }
                return sb.append(eMessage).toString();
            }
        };
    }
}
