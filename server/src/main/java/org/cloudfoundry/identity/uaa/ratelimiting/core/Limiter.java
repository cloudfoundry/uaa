package org.cloudfoundry.identity.uaa.ratelimiting.core;

import java.time.Instant;
import java.util.function.Consumer;

public interface Limiter {
    /**
     * Report if the current request should be limited.
     * <p>
     *
     * @return true - if should limit, ; otherwise: false - don't limit
     */
    boolean shouldLimit();

    @SuppressWarnings("unused")
    default void log(String requestPath, Consumer<String> logger, Instant startTime) {
        // default is don't log!
    }

    // used for logging (a long with toString)
    default CompoundKey getLimitingKey() {
        return null;
    }

    Limiter FORWARD_REQUEST = () -> false;
}
