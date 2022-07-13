package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

import java.time.Instant;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RateLimitingFactoriesSupplierWithStatusTest {
    private static final long now15_123456 = Instant.parse( "2011-01-15T12:34:56Z" ).toEpochMilli();
    private static final long now16_012345 = Instant.parse( "2011-01-16T01:23:45Z" ).toEpochMilli();
    private static final long now16_013000 = Instant.parse( "2011-01-16T01:30:00Z" ).toEpochMilli();

    @Test
    void general() {
        RateLimitingFactoriesSupplierWithStatus fsNs = RateLimitingFactoriesSupplierWithStatus.builder().build();
        assertFalse( fsNs.isRateLimitingEnabled() );
        assertNull( fsNs.getStatus() );
        assertNull( fsNs.getStatusJson() );
        fsNs = fsNs.toBuilder().status( RateLimiterStatus.NO_RATE_LIMITING ).supplier( InternalLimiterFactoriesSupplier.NOOP ).build();
        assertTrue( fsNs.isRateLimitingEnabled() );
        assertEquals(InternalLimiterFactoriesSupplier.NOOP, fsNs.getSupplier() );
        assertEquals(RateLimiterStatus.NO_RATE_LIMITING, fsNs.getStatus() );
        assertNotNull( fsNs.getStatusJson() ); // Tested else where!
    }

    @Test
    void create_updateError_update() {
        RateLimitingFactoriesSupplierWithStatus fsNs = RateLimitingFactoriesSupplierWithStatus
                .create( null, null, now15_123456, "test", false );
        assertFalse( fsNs.isRateLimitingEnabled() );
        assertNotNull( fsNs.getStatus() ); // Tested else where!
        assertNotNull( fsNs.getStatusJson() ); // Tested else where!
        assertTrue( fsNs.getStatus().hasCurrentSection() ); // content Tested else where!
        assertTrue( fsNs.getStatus().hasUpdateSection() ); // content Tested else where!
        assertNull( fsNs.getStatus().getCurrent().getError() );
        assertNull( fsNs.getStatus().getUpdate().getError() );
        assertEquals( "test", fsNs.getStatus().getFromSource() );

        fsNs = fsNs.updateError( new RateLimitingConfigException( "testy" ), now16_012345 );
        assertNotNull( fsNs.getStatus() ); // Tested else where!
        assertNotNull( fsNs.getStatusJson() ); // Tested else where!
        assertTrue( fsNs.getStatus().hasCurrentSection() ); // content Tested else where!
        assertTrue( fsNs.getStatus().hasUpdateSection() ); // content Tested else where!
        assertNull( fsNs.getStatus().getCurrent().getError() );
        assertEquals( "testy", fsNs.getStatus().getUpdate().getError() );
        assertEquals( "test", fsNs.getStatus().getFromSource() );

        fsNs = fsNs.update( null, now16_013000, "testUpdate" );
        assertNotNull( fsNs.getStatus() ); // Tested else where!
        assertNotNull( fsNs.getStatusJson() ); // Tested else where!
        assertTrue( fsNs.getStatus().hasCurrentSection() ); // content Tested else where!
        assertTrue( fsNs.getStatus().hasUpdateSection() ); // content Tested else where!
        assertNull( fsNs.getStatus().getCurrent().getError() );
        assertNull( fsNs.getStatus().getUpdate().getError() );
        assertEquals( "testUpdate", fsNs.getStatus().getFromSource() );
    }
}