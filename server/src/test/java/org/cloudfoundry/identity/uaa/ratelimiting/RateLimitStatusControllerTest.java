package org.cloudfoundry.identity.uaa.ratelimiting;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitStatusControllerTest {

    RateLimitStatusController rateLimitStatusController = new RateLimitStatusController();

    @Test
    void rateLimitStatus() {
        String responseEntity = rateLimitStatusController.rateLimitStatus();
        assertThat(responseEntity).contains("\"status\" : \"DISABLED\"");
    }
}
