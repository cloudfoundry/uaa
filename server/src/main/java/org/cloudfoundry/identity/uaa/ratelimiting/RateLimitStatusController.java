package org.cloudfoundry.identity.uaa.ratelimiting;

import org.cloudfoundry.identity.uaa.ratelimiting.core.LimiterManager;
import org.cloudfoundry.identity.uaa.ratelimiting.core.RateLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking.LimiterManagerImpl;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class RateLimitStatusController {
    private final LimiterManager status = LimiterManagerImpl.SINGLETON.getInstance();

    @GetMapping(value = {RateLimiter.STATUS_PATH, RateLimiter.STATUS_PATH+"/"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public String rateLimitStatus() {
        return status.rateLimitingStatus();
    }

}
