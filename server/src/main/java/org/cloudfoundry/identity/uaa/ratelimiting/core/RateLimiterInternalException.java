package org.cloudfoundry.identity.uaa.ratelimiting.core;

public class RateLimiterInternalException extends RuntimeException {
    public RateLimiterInternalException(String message) {
        this(message, null);
    }

    public RateLimiterInternalException(String message, Throwable cause) {
        super(message, cause);
    }
}
