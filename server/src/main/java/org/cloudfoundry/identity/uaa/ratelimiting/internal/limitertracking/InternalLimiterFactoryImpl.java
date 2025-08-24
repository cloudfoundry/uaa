package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import java.time.Instant;

import jakarta.annotation.Nonnull;
import lombok.Builder;
import lombok.Getter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.RequestsPerWindowSecs;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactory;

@Getter
public class InternalLimiterFactoryImpl implements InternalLimiterFactory {
    private final RequestsPerWindowSecs requestsPerWindow;
    private final String name;
    private final String windowType;

    public boolean isGlobal() {
        return WindowType.GLOBAL.windowType().equals(windowType);
    }

    @Builder
    public InternalLimiterFactoryImpl(RequestsPerWindowSecs requestsPerWindow,
            String windowType, String name) {
        this.requestsPerWindow = requestsPerWindow;
        this.windowType = windowType;
        this.name = name;
    }

    @Override
    @Nonnull
    public InternalLimiter newLimiter(CompoundKey compoundKey, @Nonnull Instant now) {
        return new InternalLimiter( compoundKey, getInitialRequestsRemaining(),
                getWindowEndExclusive(now, getWindowSecs()) );
    }

    // package friendly for testing
    int getInitialRequestsRemaining() {
        return getRequestsPerWindow().getMaxRequestsPerWindow();
    }

    // package friendly for testing
    int getWindowSecs() {
        return getRequestsPerWindow().getWindowSecs();
    }

    public String toString() {
        return getName() + "(" + getWindowType() + (isGlobal() ? "" : ":keyed") + ")"
                + " @ " + getRequestsPerWindow();
    }

    private Instant getWindowEndExclusive(@Nonnull Instant now, int windowSecs) {
        return now.plusSeconds(windowSecs);
    }
}
