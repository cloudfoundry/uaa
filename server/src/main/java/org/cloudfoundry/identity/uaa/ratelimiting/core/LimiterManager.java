package org.cloudfoundry.identity.uaa.ratelimiting.core;

import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;

public interface LimiterManager {

    Limiter getLimiter( RequestInfo info );
}
