package org.cloudfoundry.identity.uaa.ratelimiting.core;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import org.cloudfoundry.identity.uaa.ratelimiting.config.InitialConfig;

public interface RateLimiter {
    String STATUS_PATH = "/RateLimitingStatus";

    /**
     * @return one of the STATUS json strings when the RateLimiter is active
     */
    @NotEmpty
    String status();

    @NotNull
    Limiter checkRequest(HttpServletRequest request);

    static boolean isEnabled() {
        return InitialConfig.SINGLETON.getInstance().isRateLimitingEnabled();
    }
}
