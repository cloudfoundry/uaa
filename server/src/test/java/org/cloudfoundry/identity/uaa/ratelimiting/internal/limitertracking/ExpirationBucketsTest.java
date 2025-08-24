package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.util.NanoTimeSupplier;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking.ExpirationBuckets.BucketRingBoundsException;
import static org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking.ExpirationBuckets.ExpirationBucketMapping;

class ExpirationBucketsTest {
    NanoTimeSupplier.Mock mockCurrentTimeSupplier = new NanoTimeSupplier.Mock();
    long CURRENT_SECOND = Instant.ofEpochMilli(TimeUnit.NANOSECONDS.toMillis(mockCurrentTimeSupplier.now())).getEpochSecond();

    static class MockCompoundKeyPurger implements CompoundKeyPurger {
        Long expirationSecond;
        List<CompoundKey> compoundKeys = new ArrayList<>();

        @Override
        public boolean removeCompoundKey(CompoundKey compoundKey, long expirationSecond) {
            check(expirationSecond);
            this.expirationSecond = expirationSecond;
            compoundKeys.add(compoundKey);
            return true; // ignored - used by the tests of the "real" CompoundKeyPurger
        }

        List<CompoundKey> getCompoundKeys(long expirationSecond) {
            check(expirationSecond);
            return compoundKeys;
        }

        void clear() {
            expirationSecond = null;
            compoundKeys.clear();
        }

        private void check(long expirationSecond) {
            if ((this.expirationSecond != null) && (this.expirationSecond != expirationSecond)) {
                throw new IllegalStateException("Expected expirationSecond '" + Instant.ofEpochSecond(expirationSecond)
                        + "', but found: " + Instant.ofEpochSecond(this.expirationSecond));
            }
        }
    }

    MockCompoundKeyPurger removedKeyTracker = new MockCompoundKeyPurger();

    ExpirationBuckets buckets = new ExpirationBuckets(mockCurrentTimeSupplier,
            removedKeyTracker, 17);

    private void assertBucketMappings(int offset, long second) {
        ExpirationBucketMapping mapping = buckets.getExpirationBucketMapping();
        assertThat(mapping.getCurrentRingBucketBaseOffset()).isEqualTo(offset);
        assertThat(mapping.getCurrentRingBucketBaseSecond()).isEqualTo(second);
    }

    private void assertBadBucketSecondRequest(long second) {
        List<CompoundKey> bucket;

        try {
            bucket = buckets.getBucket(second);
        } catch (BucketRingBoundsException expected) {
            // Ignore
            return;
        }
        fail("Expected exception BucketRingBoundsException, but got bucket: " + bucket);
    }

    @Test
    void generalAssumptionsTest() {
        // 17 + 2 -> 32 buckets (next power of 2 above 19) -> masking mass of 32-1 -> 5 bits
        assertThat(buckets.getWrapAroundMask()).isEqualTo(31);

        assertThat(buckets.currentSecondNow()).isEqualTo(CURRENT_SECOND);

        long bucketBaseSecond = buckets.currentSecondNow() - 2;
        assertBucketMappings(0, bucketBaseSecond);

        assertBadBucketSecondRequest(bucketBaseSecond - 1);
        assertBadBucketSecondRequest(bucketBaseSecond + 32);
    }

    private static CompoundKey ck(String middle) {
        return CompoundKey.from("", middle, "");
    }

    @Test
    void addCompoundKeyExpirationWithExpirations() {
        buckets.addCompoundKeyExpiration(ck("Key1"), CURRENT_SECOND + 1);
        buckets.addCompoundKeyExpiration(ck("Key2"), CURRENT_SECOND + 1);
        buckets.addCompoundKeyExpiration(ck("Key1"), CURRENT_SECOND + 3);
        buckets.addCompoundKeyExpiration(ck("Key2"), CURRENT_SECOND + 4);

        processExpectedExpirationsAndAdvanceClock1Sec(); // current Sec - remember purging operates 2 seconds back
        assertBucketMappings(0, CURRENT_SECOND - 2);
        processExpectedExpirationsAndAdvanceClock1Sec();
        assertBucketMappings(1, CURRENT_SECOND - 1);
        processExpectedExpirationsAndAdvanceClock1Sec();
        assertBucketMappings(2, CURRENT_SECOND);
        processExpectedExpirationsAndAdvanceClock1Sec("Key1", "Key2");
        assertBucketMappings(3, CURRENT_SECOND + 1);
        processExpectedExpirationsAndAdvanceClock1Sec();
        assertBucketMappings(4, CURRENT_SECOND + 2);
        processExpectedExpirationsAndAdvanceClock1Sec("Key1");
        assertBucketMappings(5, CURRENT_SECOND + 3);
        processExpectedExpirationsAndAdvanceClock1Sec("Key2");
        assertBucketMappings(6, CURRENT_SECOND + 4);
        for (int i = 0; i < 32; i++) {
            processExpectedExpirationsAndAdvanceClock1Sec();
        }
        assertBucketMappings(6, CURRENT_SECOND + 36);
        for (int i = 0; i < 32; i++) {
            processExpectedExpirationsAndAdvanceClock1Sec();
        }
        assertBucketMappings(6, CURRENT_SECOND + 68);
    }

    private void processExpectedExpirationsAndAdvanceClock1Sec(String... expectedKeys) {
        buckets.processExpirations();
        long expirationSecond = Instant.ofEpochMilli(TimeUnit.NANOSECONDS.toMillis(mockCurrentTimeSupplier.now())).getEpochSecond() - 2;
        compareCompoundKeys(expirationSecond, removedKeyTracker.getCompoundKeys(expirationSecond), expectedKeys);
        removedKeyTracker.clear();
        mockCurrentTimeSupplier.add(Duration.ofSeconds(1));
    }

    private void compareCompoundKeys(long expirationSecond, List<CompoundKey> actualCompoundKeys, String[] expectedCompoundKeys) {
        if (expectedCompoundKeys.length == actualCompoundKeys.size()) {
            boolean allFound = true;
            for (String expected : expectedCompoundKeys) {
                allFound &= actualCompoundKeys.contains(ck(expected));
            }
            if (allFound) {
                return;
            }
        }
        fail("Mismatched results on Second " + (CURRENT_SECOND - expirationSecond) + ":" +
                "\n   Expected: " + Arrays.asList(expectedCompoundKeys) +
                "\n     Actual: " + actualCompoundKeys);
    }
}