package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.time.Instant;
import java.util.LinkedHashMap;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactory;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ErrorSupplierPairTest {
    private static final long now15_123456 = Instant.parse("2011-01-15T12:34:56Z").toEpochMilli();
    private static final long now16_012345 = Instant.parse("2011-01-16T01:23:45Z").toEpochMilli();

    @Test
    void map_create() {
        ErrorSupplierPair pair = ErrorSupplierPair.with(new RateLimitingConfigException( "testy" ));
        RateLimitingFactoriesSupplierWithStatus fsNs = pair.map(null, "map_create", now15_123456);
        assertTrue(fsNs.isRateLimitingEnabled());
        assertTrue(fsNs.getSupplier().isSupplierNOOP());
        assertNotNull(fsNs.getStatus()); // Tested else where!
        assertNotNull(fsNs.getStatusJson()); // Tested else where!
        assertTrue(fsNs.getStatus().hasCurrentSection()); // content Tested else where!
        assertEquals("testy", fsNs.getStatus().getCurrent().getError());
        assertEquals(RateLimiterStatus.toISO8601ZtoSec(now15_123456), fsNs.getStatus().getCurrent().getAsOf());
        assertEquals("map_create", fsNs.getStatus().getFromSource());
    }

    @Test
    void map_update() {
        RateLimitingFactoriesSupplierWithStatus existing = new RateLimitingFactoriesSupplierWithStatus( InternalLimiterFactoriesSupplier.NOOP, RateLimiterStatus.noRateLimiting(now15_123456) );
        ErrorSupplierPair pair = ErrorSupplierPair.with(InternalLimiterFactoriesSupplier.NOOP);
        RateLimitingFactoriesSupplierWithStatus fsNs = pair.map(existing, "map_update", now16_012345);

        assertTrue(fsNs.isRateLimitingEnabled());
        assertTrue(fsNs.getSupplier().isSupplierNOOP());
        assertNotNull(fsNs.getStatus()); // Tested else where!
        assertNotNull(fsNs.getStatusJson()); // Tested else where!
        assertTrue(fsNs.getStatus().hasCurrentSection()); // content Tested else where!
        assertNull(fsNs.getStatus().getCurrent().getError());
        assertEquals(RateLimiterStatus.toISO8601ZtoSec(now15_123456), fsNs.getStatus().getCurrent().getAsOf());
        assertNull(fsNs.getStatus().getFromSource()); //TODO Check
    }
}