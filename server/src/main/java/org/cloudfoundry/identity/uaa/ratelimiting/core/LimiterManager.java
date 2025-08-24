package org.cloudfoundry.identity.uaa.ratelimiting.core;

import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;

public interface LimiterManager {
    String rateLimitingStatus();

    Limiter getLimiter(RequestInfo info);
}
