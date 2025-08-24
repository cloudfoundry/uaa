package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

import java.time.Instant;

import jakarta.annotation.Nonnull;
import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;

public interface InternalLimiterFactory {
    /**
     * Create an internal limiter.
     *
     * @param compoundKey used for tracking information
     * @param now         non-Null Instant for the current time.
     * @return internal limiter (not Null)
     */
    @Nonnull
    InternalLimiter newLimiter(CompoundKey compoundKey, @Nonnull Instant now);
}
