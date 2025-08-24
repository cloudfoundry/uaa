package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.RequestsPerWindowSecs;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.util.NanoTimeSupplier;
import org.junit.jupiter.api.Test;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;

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

    LimiterByCompoundKey limiterByCompoundKey = new LimiterByCompoundKey(mockCurrentTimeSupplier);

    private InternalLimiter getLimiter(String callerId) {
        CompoundKey compoundKey = CompoundKey.from(LIMITER_NAME, WINDOW_TYPE, callerId);
        InternalLimiter limiter = limiterByCompoundKey.get(compoundKey, factory, limiterCreationTracker);
        assertThat(limiter).isNotNull();
        return limiter;
    }

    private Params addLimiterAndAdvanceClockBy1Sec(String callerId) {
        InternalLimiter limiter = getLimiter(callerId);
        mockCurrentTimeSupplier.add(Duration.ofSeconds(1));
        return new Params(limiter.getCompoundKey(), limiter.getWindowEndExclusive().getEpochSecond());
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

        assertThat(callerId11).isEqualTo(callerId1);
        assertThat(callerId12).isEqualTo(callerId1);
        assertThat(callerId13).isEqualTo(callerId1);
        assertThat(limiterCreationTracker.entryCount()).isOne();
        assertThat(limiterCreationTracker.callsCount(callerId1)).isEqualTo(2);

        String callerId2 = "callerId2";
        String callerId21 = getLimiterAndAdvanceClockBy1Sec(callerId2, callerId1); // callerId2 New & existing callerId1
        String callerId22 = getLimiterAndAdvanceClockBy1Sec(callerId2, callerId1); // callerId2 existing & new callerId1
        String callerId23 = getLimiterAndAdvanceClockBy1Sec(callerId2, callerId1); // callerId2 New & existing callerId1
        String callerId24 = getLimiterAndAdvanceClockBy1Sec(callerId2, callerId1); // callerId2 existing & new callerId1
        String callerId25 = getLimiterAndAdvanceClockBy1Sec(callerId2, callerId1); // callerId2 New & existing callerId1

        assertThat(callerId21).isEqualTo(callerId2);
        assertThat(callerId22).isEqualTo(callerId2);
        assertThat(callerId23).isEqualTo(callerId2);
        assertThat(callerId24).isEqualTo(callerId2);
        assertThat(callerId25).isEqualTo(callerId2);
        assertThat(limiterCreationTracker.entryCount()).isEqualTo(2);
        assertThat(limiterCreationTracker.callsCount(callerId1)).isEqualTo(4);
        assertThat(limiterCreationTracker.callsCount(callerId2)).isEqualTo(3);
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

        assertThat(p2).isEqualTo(p1);
        assertThat(p3).isNotEqualTo(p1);
        assertThat(p1.equalsCompoundKey(p3)).isTrue();

        assertThat(limiterByCompoundKey.removeCompoundKey(p1.compoundKey, p1.expectedExpirationSecond)).isFalse();
        assertThat(limiterByCompoundKey.removeCompoundKey(p2.compoundKey, p2.expectedExpirationSecond)).isFalse();
        assertThat(limiterByCompoundKey.removeCompoundKey(p2.compoundKey, p3.expectedExpirationSecond)).isTrue();
    }
}