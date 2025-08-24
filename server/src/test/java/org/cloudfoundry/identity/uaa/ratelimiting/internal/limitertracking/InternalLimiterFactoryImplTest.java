package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.RequestsPerWindowSecs;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.util.NanoTimeSupplier;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class InternalLimiterFactoryImplTest {
    private static final String GLOBAL = WindowType.GLOBAL.windowType();
    private static final String NOT_GLOBAL = "!" + GLOBAL;
    private static final String NAME = "Test";
    private static final String REQUESTS_PER_WINDOW = "5r/2s";

    private final NanoTimeSupplier.Mock mockCurrentTimeSupplier = new NanoTimeSupplier.Mock();

    @Test
    void constructorOptionsTest() {
        RequestsPerWindowSecs requests = RequestsPerWindowSecs.from("limiterName", "testData", REQUESTS_PER_WINDOW);
        InternalLimiterFactoryImpl factory = InternalLimiterFactoryImpl.builder()
                .name(NAME).windowType(GLOBAL).requestsPerWindow(requests)
                .build();

        assertThat(factory.getRequestsPerWindow()).hasToString(REQUESTS_PER_WINDOW);
        assertThat(factory.getName()).isEqualTo(NAME);
        assertThat(factory.getWindowType()).isEqualTo(GLOBAL);
        assertThat(factory.isGlobal()).isTrue();

        factory = InternalLimiterFactoryImpl.builder()
                .name(NAME).windowType(NOT_GLOBAL).requestsPerWindow(requests)
                .build();
        assertThat(factory.getRequestsPerWindow()).hasToString(REQUESTS_PER_WINDOW);
        assertThat(factory.getName()).isEqualTo(NAME);
        assertThat(factory.getWindowType()).isEqualTo(NOT_GLOBAL);
        assertThat(factory.isGlobal()).isFalse();

        int windowSecs = factory.getWindowSecs();
        CompoundKey compoundKey = CompoundKey.from(NAME, factory.getWindowType(), "whatever");

        InternalLimiter limiter = factory.newLimiter(compoundKey, mockCurrentTimeSupplier.nowAsInstant());
        assertThat(limiter.getCompoundKey()).isEqualTo(compoundKey);
        assertThat(limiter.getRequestsRemaining()).isEqualTo(factory.getInitialRequestsRemaining());

        mockCurrentTimeSupplier.add(windowSecs * 1000000000L); // Nanos
        assertThat(limiter.getWindowEndExclusive()).isEqualTo(mockCurrentTimeSupplier.nowAsInstant());
    }
}
