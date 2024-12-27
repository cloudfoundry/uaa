package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.junit.jupiter.api.Test;

class RateLimitingFactoriesSupplierWithStatusTest {
    private static final long now15_123456 = Instant.parse("2011-01-15T12:34:56Z").toEpochMilli();
    private static final long now16_012345 = Instant.parse("2011-01-16T01:23:45Z").toEpochMilli();
    private static final long now16_013000 = Instant.parse("2011-01-16T01:30:00Z").toEpochMilli();

    @Test
    void general() {
        RateLimitingFactoriesSupplierWithStatus fsNs = RateLimitingFactoriesSupplierWithStatus.builder().build();
        assertFalse(fsNs.isRateLimitingEnabled());
        assertNull(fsNs.getStatus());
        assertNull(fsNs.getStatusJson());
        fsNs = fsNs.toBuilder().status(RateLimiterStatus.NO_RATE_LIMITING).supplier(InternalLimiterFactoriesSupplier.NOOP).build();
        assertTrue(fsNs.isRateLimitingEnabled());
        assertEquals(InternalLimiterFactoriesSupplier.NOOP, fsNs.getSupplier());
        assertEquals(RateLimiterStatus.NO_RATE_LIMITING, fsNs.getStatus());
        assertNotNull(fsNs.getStatusJson()); // Tested else where!
    }

    @Test
    void create_updateError_update() {
        RateLimitingFactoriesSupplierWithStatus fsNs = RateLimitingFactoriesSupplierWithStatus
                .create(null, null, now15_123456, "test");
        assertFalse(fsNs.isRateLimitingEnabled());
        assertNotNull(fsNs.getStatus()); // Tested else where!
        assertNotNull(fsNs.getStatusJson()); // Tested else where!
        assertTrue(fsNs.getStatus().hasCurrentSection()); // content Tested else where!
        assertNull(fsNs.getStatus().getCurrent().getError());
        assertEquals("test", fsNs.getStatus().getFromSource());

        fsNs = fsNs.updateError(new RateLimitingConfigException( "testy" ));
        assertNotNull(fsNs.getStatus()); // Tested else where!
        assertNotNull(fsNs.getStatusJson()); // Tested else where!
        assertTrue(fsNs.getStatus().hasCurrentSection()); // content Tested else where!
        assertNull(fsNs.getStatus().getCurrent().getError());
        assertEquals("test", fsNs.getStatus().getFromSource());

        fsNs = fsNs.update();
        assertNotNull(fsNs.getStatus()); // Tested else where!
        assertNotNull(fsNs.getStatusJson()); // Tested else where!
        assertTrue(fsNs.getStatus().hasCurrentSection()); // content Tested else where!
        assertNull(fsNs.getStatus().getCurrent().getError());
        assertEquals("test", fsNs.getStatus().getFromSource());
    }
}