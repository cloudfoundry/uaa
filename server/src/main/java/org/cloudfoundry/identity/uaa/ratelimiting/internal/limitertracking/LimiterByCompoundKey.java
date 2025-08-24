package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactory;
import org.cloudfoundry.identity.uaa.ratelimiting.util.NanoTimeSupplier;

public class LimiterByCompoundKey implements CompoundKeyPurger {
    private final Map<CompoundKey, InternalLimiter> map = new HashMap<>();
    private final NanoTimeSupplier currentTimeSupplier;

    public LimiterByCompoundKey(NanoTimeSupplier currentTimeSupplier) {
        this.currentTimeSupplier = currentTimeSupplier;
    }

    @Override
    public synchronized boolean removeCompoundKey(CompoundKey compoundKey, long expectedExpirationSecond) {
        InternalLimiter limiter = map.get(compoundKey);
        if (limiter != null) {
            long limiterExpirationSecond = limiter.getWindowEndExclusive().getEpochSecond();
            if (expectedExpirationSecond == limiterExpirationSecond) {
                map.remove(compoundKey);
                return true;
            }
        }
        return false;
    }

    public InternalLimiter get(CompoundKey compoundKey, InternalLimiterFactory factory,
            CompoundKeyExpirationAdder compoundKeyExpirationAdder) {
        InternalLimiter existingLimiter = get(compoundKey);
        Instant now = currentTimeSupplier.nowAsInstant();
        if ((existingLimiter != null) && !existingLimiter.isExpired(now)) {
            return existingLimiter;
        }
        InternalLimiter plannedNewLimiter = factory.newLimiter(compoundKey, now);
        InternalLimiter actualNewLimiter = put(compoundKey, existingLimiter, plannedNewLimiter);
        if (actualNewLimiter == plannedNewLimiter) {
            compoundKeyExpirationAdder.addCompoundKeyExpiration(compoundKey,
                    actualNewLimiter.getWindowEndExclusive().getEpochSecond());
        }
        return actualNewLimiter;
    }

    private synchronized InternalLimiter get(CompoundKey compoundKey) {
        return map.get(compoundKey);
    }

    private synchronized InternalLimiter put(CompoundKey compoundKey, InternalLimiter existingLimiter, InternalLimiter newLimiter) {
        InternalLimiter mappedLimiter = map.get(compoundKey);
        if (existingLimiter != mappedLimiter) { // Our Thread paused between get and put, and another thread updated map already
            return mappedLimiter; // return updated
        }
        map.put(compoundKey, newLimiter);
        return newLimiter;
    }
}
