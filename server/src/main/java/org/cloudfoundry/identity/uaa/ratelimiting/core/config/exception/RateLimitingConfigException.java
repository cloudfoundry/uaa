package org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception;

public class RateLimitingConfigException extends IllegalStateException {
    private final Throwable actualCause;

    public RateLimitingConfigException(String message) {
        super(message);
        actualCause = null;
    }

    public RateLimitingConfigException(String message, Throwable cause) {
        super(message, cause);
        actualCause = cause;
    }

    public Throwable getActualCause() {
        return actualCause;
    }
}
