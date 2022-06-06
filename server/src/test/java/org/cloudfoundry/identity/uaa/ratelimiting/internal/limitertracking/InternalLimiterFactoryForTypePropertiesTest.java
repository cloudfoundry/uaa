package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.RequestsPerWindowSecs;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.util.MillisTimeSupplier;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class InternalLimiterFactoryForTypePropertiesTest {
    private static final String Global = WindowType.GLOBAL.windowType();
    private static final String NotGlobal = "!" + Global;
    private static final String NAME = "Test";
    private static final String REQUESTS_PER_WINDOW = "5r/2s";

    private final MillisTimeSupplier.Mock mockCurrentTimeSupplier = new MillisTimeSupplier.Mock();

    @Test
    public void constructorOptionsTest() {
        RequestsPerWindowSecs requests = RequestsPerWindowSecs.from( "propertyName", "testData", REQUESTS_PER_WINDOW );
        InternalLimiterFactoryImpl factory = InternalLimiterFactoryImpl.builder()
                .name( NAME ).windowType( Global ).requestsPerWindow( requests )
                .build();

        assertEquals( REQUESTS_PER_WINDOW, factory.getRequestsPerWindow().toString() );
        assertEquals( NAME, factory.getName() );
        assertEquals( Global, factory.getWindowType() );
        assertTrue( factory.isGlobal() );

        factory = InternalLimiterFactoryImpl.builder()
                .name( NAME ).windowType( NotGlobal ).requestsPerWindow( requests )
                .build();

        assertEquals( REQUESTS_PER_WINDOW, factory.getRequestsPerWindow().toString() );
        assertEquals( NAME, factory.getName() );
        assertEquals( NotGlobal, factory.getWindowType() );
        assertFalse( factory.isGlobal() );

        int windowSecs = factory.getWindowSecs();
        CompoundKey compoundKey = CompoundKey.from( NAME, factory.getWindowType(), "whatever" );

        InternalLimiter limiter = factory.newLimiter( compoundKey, mockCurrentTimeSupplier.nowAsInstant() );

        assertEquals( compoundKey, limiter.getCompoundKey() );
        assertEquals( factory.getInitialRequestsRemaining(), limiter.getRequestsRemaining() );

        mockCurrentTimeSupplier.add( windowSecs * 1000L ); // Millis

        assertEquals( mockCurrentTimeSupplier.nowAsInstant(), limiter.getWindowEndExclusive() );
    }
}