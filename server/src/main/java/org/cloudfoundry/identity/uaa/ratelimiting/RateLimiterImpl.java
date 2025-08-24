package org.cloudfoundry.identity.uaa.ratelimiting;

import jakarta.servlet.http.HttpServletRequest;

import org.cloudfoundry.identity.uaa.ratelimiting.core.Limiter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LimiterManager;
import org.cloudfoundry.identity.uaa.ratelimiting.core.RateLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfoImpl;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking.LimiterManagerImpl;

public class RateLimiterImpl implements RateLimiter {
    private final LimiterManager manager;

    public RateLimiterImpl(LimiterManager manager) {
        this.manager = manager;
    }

    public RateLimiterImpl() {
        this(LimiterManagerImpl.SINGLETON.getInstance());
    }

    @Override
    public String status() {
        return manager.rateLimitingStatus();
    }

    @Override
    public Limiter checkRequest(HttpServletRequest request) {
        return getLimiter(RequestInfoImpl.from(request));
    }

    // package friendly for testing
    Limiter getLimiter(RequestInfo info) {
        return manager.getLimiter(info); // should NOT be null
    }
}
