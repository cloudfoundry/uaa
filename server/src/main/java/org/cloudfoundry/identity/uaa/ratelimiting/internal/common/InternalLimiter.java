package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

import java.time.Instant;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.annotation.Nonnull;
import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;

public class InternalLimiter {
    // Uses an "inner" Lock Object to discourage other developers from messing with the lock order
    private final Object lockObject = new Object();
    // Used for tracking information (and toString - debugging context)
    private final CompoundKey compoundKey;
    // Used by the Expiration infrastructure to determine if this is still the instance added to the Expiration infrastructure and should be deleted
    private final Instant windowEndExclusive;
    // Tracks requestsRemaining - also Used for toString to determine the minimum requests remaining for the multi InternalLimiter implementation(s)
    private final AtomicInteger requestsRemaining;

    public InternalLimiter(CompoundKey compoundKey, int initialRequestsRemaining, Instant windowEndExclusive) {
        this.compoundKey = compoundKey;
        this.windowEndExclusive = windowEndExclusive;
        requestsRemaining = new AtomicInteger( initialRequestsRemaining );
    }

    /**
     * Used to determine if this limiter should be replaced
     */
    public boolean isExpired(Instant now) {
        return !now.isBefore(windowEndExclusive);
    }

    /**
     * Recursively call the subsequent InternalLimiter's shouldLimit based on <code>ils</code> entry for <code>indexOffset</code> is <code>this</code>.
     * <p>
     * If <code>true</code> returned: none of the InternalLimiter(s) should have their <code>requestsRemaining</code> reduced
     * If <code>false</code> returned: ALL the InternalLimiter(s) should have their <code>requestsRemaining</code> reduced
     *
     * @param orderedInternalLimiters an appropriately ordered (non-null) iterator of <code>InternalLimiter</code>(s) (no entries null) to be called recursively
     * @return true - if should limit, ; otherwise - false, don't limit
     */
    public boolean shouldLimit(@Nonnull Iterator<InternalLimiter> orderedInternalLimiters, @Nonnull LimiterImpl limiter) {
        // Note: synchronization here NOT for Memory barriers, but for temporary exclusive access!
        synchronized (lockObject) { // build up synchronization locks in list order!
            if (limiter.recordLimiting(getRequestsRemaining() < 1)) {
                return true; // Limit - don't decrement
            }
            // Not Limiting, so check on next Recursively
            if (orderedInternalLimiters.hasNext() && orderedInternalLimiters.next().shouldLimit(orderedInternalLimiters, limiter)) { // still in range - so recurse
                return true; // Limit - subsequent InternalLimiter says limit - so don't decrement
            }
            // all InternalLimiter(s) in the Iterator indicated have remaining requests, so decrement each as we unwind
            limiter.recordRemaining(decrementRequestsRemaining());
        }
        return false;
    }

    public CompoundKey getCompoundKey() {
        return compoundKey;
    }

    public int getRequestsRemaining() {
        return requestsRemaining.get();
    }

    public Instant getWindowEndExclusive() {
        return windowEndExclusive;
    }

    protected int decrementRequestsRemaining() {
        return requestsRemaining.decrementAndGet();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder( "InternalLimiter: " );
        sb.append(getRequestsRemaining()).append(" remaining till ").append(getWindowEndExclusive());
        if (isExpired(Instant.now())) {
            sb.append("(expired)");
        }
        sb.append(" for ").append(getCompoundKey());
        return sb.toString();
    }
}
