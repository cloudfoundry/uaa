package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

public interface LimiterFactorySupplierUpdatable {
    void update( InternalLimiterFactoriesSupplier factoryByTypeSupplier );

    default void startBackgroundProcessing() {
    }

    default void shutdownBackgroundProcessing() {
    }
}
