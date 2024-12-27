package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.RequestsPerWindowSecs;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.util.NanoTimeSupplier;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InternalLimiterFactoryImplTest {
    private static final String Global = WindowType.GLOBAL.windowType();
    private static final String NotGlobal = "!" + Global;
    private static final String NAME = "Test";
    private static final String REQUESTS_PER_WINDOW = "5r/2s";

    private final NanoTimeSupplier.Mock mockCurrentTimeSupplier = new NanoTimeSupplier.Mock();

    @Test
    void constructorOptionsTest() {
        RequestsPerWindowSecs requests = RequestsPerWindowSecs.from("limiterName", "testData", REQUESTS_PER_WINDOW);
        InternalLimiterFactoryImpl factory = InternalLimiterFactoryImpl.builder()
                .name(NAME).windowType(Global).requestsPerWindow(requests)
                .build();

        assertEquals(REQUESTS_PER_WINDOW, factory.getRequestsPerWindow().toString());
        assertEquals(NAME, factory.getName());
        assertEquals(Global, factory.getWindowType());
        assertTrue(factory.isGlobal());

        factory = InternalLimiterFactoryImpl.builder()
                .name(NAME).windowType(NotGlobal).requestsPerWindow(requests)
                .build();

        assertEquals(REQUESTS_PER_WINDOW, factory.getRequestsPerWindow().toString());
        assertEquals(NAME, factory.getName());
        assertEquals(NotGlobal, factory.getWindowType());
        assertFalse(factory.isGlobal());

        int windowSecs = factory.getWindowSecs();
        CompoundKey compoundKey = CompoundKey.from(NAME, factory.getWindowType(), "whatever");

        InternalLimiter limiter = factory.newLimiter(compoundKey, mockCurrentTimeSupplier.nowAsInstant());

        assertEquals(compoundKey, limiter.getCompoundKey());
        assertEquals(factory.getInitialRequestsRemaining(), limiter.getRequestsRemaining());

        mockCurrentTimeSupplier.add(windowSecs * 1000000000L); // Nanos

        assertEquals(mockCurrentTimeSupplier.nowAsInstant(), limiter.getWindowEndExclusive());
    }
}