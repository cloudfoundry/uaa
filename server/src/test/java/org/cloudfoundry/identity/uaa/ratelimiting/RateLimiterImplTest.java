package org.cloudfoundry.identity.uaa.ratelimiting;

import org.cloudfoundry.identity.uaa.ratelimiting.core.Limiter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LimiterManager;
import org.cloudfoundry.identity.uaa.ratelimiting.core.RateLimiterInternalException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

class RateLimiterImplTest {
    private static class MockLimiterManager implements LimiterManager {
        public Integer maxRequestsRemaining;

        @Override
        public String rateLimitingStatus() {
            return "Mocked";
        }

        @Override
        public Limiter getLimiter(RequestInfo info) {
            return () -> {
                if (maxRequestsRemaining == null) {
                    throw new RateLimiterInternalException("maxRequestsRemaining not set!");
                }
                return maxRequestsRemaining < 1;
            };
        }
    }

    private final MockLimiterManager manager = new MockLimiterManager();

    private final RateLimiterImpl rateLimiter = new RateLimiterImpl(manager);

    private final RequestInfo requestInfo = mock(RequestInfo.class);

    @Test
    void internalExceptionTest() {
        assertThatExceptionOfType(RateLimiterInternalException.class).isThrownBy(() -> check(null)); // Force Error
    }

    @Test
    void dontLimitTest() {
        assertThat(check(1)).isFalse(); // still remaining requests -> Don't limit
    }

    @Test
    void limitTest() {
        assertThat(check(0)).isTrue(); // No remaining requests -> Limit
    }

    boolean check(Integer maxRequestsRemaining) {
        manager.maxRequestsRemaining = maxRequestsRemaining;
        return rateLimiter.getLimiter(requestInfo).shouldLimit();
    }
}