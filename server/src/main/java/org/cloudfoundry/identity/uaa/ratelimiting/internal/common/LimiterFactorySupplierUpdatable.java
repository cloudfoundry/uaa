package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

import lombok.NonNull;

public interface LimiterFactorySupplierUpdatable {
    /**
     * Apply an updated RateLimitingConfigurationWithStatus (includes InternalLimiterFactoriesSupplier, status, & possible error).
     *
     * @param configWithStatus not null - but InternalLimiterFactoriesSupplier may be the NOOP version (NOT limiting)
     */
    void update(@NonNull RateLimitingFactoriesSupplierWithStatus configWithStatus);

    default void startBackgroundProcessing() {
    }

    default void shutdownBackgroundProcessing() {
    }
}
