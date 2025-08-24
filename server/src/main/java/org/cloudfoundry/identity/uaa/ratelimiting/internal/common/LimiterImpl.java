package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.function.Consumer;
import jakarta.validation.constraints.NotEmpty;

import lombok.NonNull;
import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.Limiter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;

public final class LimiterImpl implements Limiter {
    private static final String NOT_LIMITED = "forward   "; // these three constant values should be the same length
    private static final String LIMITED = "--LIMIT-- ";
    private static final String NOT_CALLED = "noCheck   ";

    private final LoggingOption loggingOption;
    private final List<CompoundKey> orderedLimiterKeys;
    private final Boolean[] calledAndLimited;
    private final int[] remaining;
    private int updateIndex;
    private boolean limiting;
    private int indexOfLimiting;

    private LimiterImpl(LoggingOption loggingOption, List<InternalLimiter> limiters) {
        this.loggingOption = LoggingOption.deNull(loggingOption);
        int count = limiters.size();
        // size the arrays and list from the (1-n) InternalLimiter.
        remaining = new int[count];
        calledAndLimited = new Boolean[count];
        orderedLimiterKeys = new ArrayList<>( count );
        // populate the <code>CompoundKeys</code> from the limiters
        for (InternalLimiter limiter : limiters) {
            orderedLimiterKeys.add(limiter.getCompoundKey());
        }
    }

    /**
     * method to constructor and populate a LimiterImpl - note: .
     * <p>
     * Note: the list of <code>InternalLimiter</code> must be appropriately ordered, see <code>InternalLimiterFactoriesSupplier</code for more details.
     *
     * @param iLimiters     an appropriately ordered (non-empty) list of InternalLimiter(s) (no entries null)
     * @param loggingOption a non-Null enum that indicates the logging approach
     */
    public static LimiterImpl from(@NotEmpty List<InternalLimiter> iLimiters, @NonNull LoggingOption loggingOption) {
        LimiterImpl limiter = new LimiterImpl( loggingOption, iLimiters );
        Iterator<InternalLimiter> it = iLimiters.iterator();
        it.next().shouldLimit(it, limiter);
        return limiter;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder().append("Limiter: ");
        if (limiting) {
            sb.append(LIMITED);
        }
        for (int i = 0; i < orderedLimiterKeys.size(); i++) {
            CompoundKey compoundKey = orderedLimiterKeys.get(i);
            Boolean limited = calledAndLimited[i];
            sb.append('\n');
            if (limited == null) {
                sb.append(NOT_CALLED);
            } else if (!limited) {
                sb.append(NOT_LIMITED);
            } else {
                sb.append(LIMITED);
            }
            sb.append(compoundKey);
            if (!limiting) {
                sb.append(" (").append(remaining[i]).append(')');
            }
        }
        return sb.toString();
    }

    @Override
    public boolean shouldLimit() {
        return limiting;
    }

    @Override
    public void log(String requestPath, Consumer<String> logger, Instant startTime) {
        Instant endTime = startTime == null ? null : Instant.now();
        loggingOption.log(requestPath, logger, startTime, this, endTime);
    }

    @Override
    public CompoundKey getLimitingKey() {
        return orderedLimiterKeys.get(indexOfLimiting);
    }

    // package friendly for testing

    /**
     * Called by <code>InternalLimiter</code>(s) (in order) so can record should limit and which limiters were called!
     *
     * @param limiting if the current call is indicating should limit
     * @return the value of <code>limiting</code>
     */
    // package friendly so InternalLimiter can call it!
    boolean recordLimiting(boolean limiting) {
        if (limiting) {
            this.limiting = true;
            indexOfLimiting = updateIndex;
        }
        calledAndLimited[updateIndex++] = limiting;
        return limiting;
    }

    /**
     * Called by <code>InternalLimiter</code>(s) (in REVERSE order) IF not limiting!
     *
     * @param remaining request (after decrement)
     */
    // package friendly so InternalLimiter can call it!
    void recordRemaining(int remaining) {
        this.remaining[--updateIndex] = remaining;
    }
}
