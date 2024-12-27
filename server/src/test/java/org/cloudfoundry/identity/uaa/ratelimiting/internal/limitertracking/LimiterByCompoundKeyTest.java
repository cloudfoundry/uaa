package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.RequestsPerWindowSecs;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.util.NanoTimeSupplier;
import org.junit.jupiter.api.Test;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.junit.jupiter.api.Assertions.*;

class LimiterByCompoundKeyTest {
    private static final String WINDOW_TYPE = WindowType.NON_GLOBAL.CredentialsID.windowType();
    private static final String LIMITER_NAME = "Test";
    private static final String REQUESTS_PER_WINDOW = "5r/2s";

    NanoTimeSupplier.Mock mockCurrentTimeSupplier = new NanoTimeSupplier.Mock();

    static class MockCompoundKeyExpirationAdder implements CompoundKeyExpirationAdder {
        MultiValueMap<CompoundKey, String> calls = new LinkedMultiValueMap<>();

        @Override
        public void addCompoundKeyExpiration(CompoundKey compoundKey, long expirationSecond) {
            calls.add(compoundKey, Instant.ofEpochSecond(expirationSecond).toString());
        }

        int entryCount() {
            return calls.size();
        }

        int callsCount(String callerID) {
            CompoundKey compoundKey = CompoundKey.from(LIMITER_NAME, WINDOW_TYPE, callerID);
            List<String> values = calls.get(compoundKey);
            return values == null ? 0 : values.size();
        }
    }

    MockCompoundKeyExpirationAdder limiterCreationTracker = new MockCompoundKeyExpirationAdder();

    RequestsPerWindowSecs requests = RequestsPerWindowSecs.from("theName", "testData", REQUESTS_PER_WINDOW);

    InternalLimiterFactoryImpl factory = InternalLimiterFactoryImpl.builder()
            .windowType(WINDOW_TYPE).name(LIMITER_NAME).requestsPerWindow(requests)
            .build();

    LimiterByCompoundKey limiterByCompoundKey = new LimiterByCompoundKey( mockCurrentTimeSupplier );

    private InternalLimiter getLimiter(String callerId) {
        CompoundKey compoundKey = CompoundKey.from(LIMITER_NAME, WINDOW_TYPE, callerId);
        InternalLimiter limiter = limiterByCompoundKey.get(compoundKey, factory, limiterCreationTracker);
        assertNotNull(limiter);
        return limiter;
    }

    private Params addLimiterAndAdvanceClockBy1Sec(String callerId) {
        InternalLimiter limiter = getLimiter(callerId);
        mockCurrentTimeSupplier.add(Duration.ofSeconds(1));
        return new Params( limiter.getCompoundKey(), limiter.getWindowEndExclusive().getEpochSecond() );
    }

    private String getLimiterAndAdvanceClockBy1Sec(String callerId, String... additionalCallerIds) {
        getLimiter(callerId);
        for (String additionalCallerId : additionalCallerIds) {
            getLimiter(additionalCallerId);
        }
        mockCurrentTimeSupplier.add(Duration.ofSeconds(1));
        return callerId;
    }

    @Test
    void getTest() {
        String callerId1 = "callerId1";
        String callerId11 = getLimiterAndAdvanceClockBy1Sec(callerId1); // New
        String callerId12 = getLimiterAndAdvanceClockBy1Sec(callerId1); // existing
        String callerId13 = getLimiterAndAdvanceClockBy1Sec(callerId1); // New (prev should be expired)

        assertEquals(callerId1, callerId11);
        assertEquals(callerId1, callerId12);
        assertEquals(callerId1, callerId13);
        assertEquals(1, limiterCreationTracker.entryCount());
        assertEquals(2, limiterCreationTracker.callsCount(callerId1));

        String callerId2 = "callerId2";
        String callerId21 = getLimiterAndAdvanceClockBy1Sec(callerId2, callerId1); // callerId2 New & existing callerId1
        String callerId22 = getLimiterAndAdvanceClockBy1Sec(callerId2, callerId1); // callerId2 existing & new callerId1
        String callerId23 = getLimiterAndAdvanceClockBy1Sec(callerId2, callerId1); // callerId2 New & existing callerId1
        String callerId24 = getLimiterAndAdvanceClockBy1Sec(callerId2, callerId1); // callerId2 existing & new callerId1
        String callerId25 = getLimiterAndAdvanceClockBy1Sec(callerId2, callerId1); // callerId2 New & existing callerId1

        assertEquals(callerId2, callerId21);
        assertEquals(callerId2, callerId22);
        assertEquals(callerId2, callerId23);
        assertEquals(callerId2, callerId24);
        assertEquals(callerId2, callerId25);
        assertEquals(2, limiterCreationTracker.entryCount());
        assertEquals(4, limiterCreationTracker.callsCount(callerId1));
        assertEquals(3, limiterCreationTracker.callsCount(callerId2));
    }

    private static class Params {
        CompoundKey compoundKey;
        long expectedExpirationSecond;

        Params(CompoundKey pCompoundKey, long pExpectedExpirationSecond) {
            compoundKey = pCompoundKey;
            expectedExpirationSecond = pExpectedExpirationSecond;
        }

        public boolean equals(Object o) {
            return (o instanceof Params p) && equals(p);
        }

        public boolean equals(Params them) {
            return (this.expectedExpirationSecond == them.expectedExpirationSecond) &&
                    equalsCompoundKey(them);
        }

        private boolean equalsCompoundKey(Params them) {
            return Objects.equals(this.compoundKey, them.compoundKey);
        }
    }

    @Test
    void removeCompoundKeyTest() {
        String callerId = "callerID";

        Params p1 = addLimiterAndAdvanceClockBy1Sec(callerId);
        Params p2 = addLimiterAndAdvanceClockBy1Sec(callerId);
        Params p3 = addLimiterAndAdvanceClockBy1Sec(callerId);

        assertEquals(p1, p2);
        assertNotEquals(p1, p3);
        assertTrue(p1.equalsCompoundKey(p3));

        assertFalse(limiterByCompoundKey.removeCompoundKey(p1.compoundKey, p1.expectedExpirationSecond));
        assertFalse(limiterByCompoundKey.removeCompoundKey(p2.compoundKey, p2.expectedExpirationSecond));
        assertTrue(limiterByCompoundKey.removeCompoundKey(p2.compoundKey, p3.expectedExpirationSecond));
    }
}