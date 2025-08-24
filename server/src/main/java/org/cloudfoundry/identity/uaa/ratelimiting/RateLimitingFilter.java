package org.cloudfoundry.identity.uaa.ratelimiting;

import lombok.RequiredArgsConstructor;
import org.cloudfoundry.identity.uaa.ratelimiting.core.Limiter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.RateLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.Enumeration;

public class RateLimitingFilter extends HttpFilter {
    private static final Logger log = LoggerFactory.getLogger(RateLimitingFilter.class);

    public static final String RATE_LIMIT_ERROR_ATTRIBUTE = "RATE_LIMIT_ERROR";

    @SuppressWarnings("unused")
    // Not really unused, called by container to create Filter
    public RateLimitingFilter() // default and production constructor
            throws ServletException {
        this(RateLimiter.isEnabled() ? new RateLimiterImpl() : null);
    }

    interface Filterer {
        String status();

        void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException;
    }

    private final transient Filterer filterer;

    RateLimitingFilter(RateLimiter rateLimiter) // flexible (real-actual and testing) constructor
            throws ServletException {
        filterer = rateLimiter == null ?
                new NoLimitingFilter( RateLimiterStatus.NO_RATE_LIMITING.toString() ) :
                new WithLimitingFilter( rateLimiter );
        init(new FilterConfig() {
            @Override
            public String getFilterName() {
                return RateLimitingFilter.class.getName();
            }

            @Override
            public ServletContext getServletContext() {
                return null;
            }

            @Override
            public String getInitParameter(String name) {
                return null;
            }

            @Override
            public Enumeration<String> getInitParameterNames() {
                return Collections.emptyEnumeration();
            }
        });
    }

    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!RateLimiter.STATUS_PATH.equals(request.getServletPath())) {
            filterer.doFilter(request, response, filterChain);
        } else {
            filterChain.doFilter(request, response);
        }
    }

    @RequiredArgsConstructor
    static class NoLimitingFilter implements Filterer {
        private final String status;

        @Override
        public String status() {
            return status;
        }

        @Override
        public void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {
            filterChain.doFilter(request, response); // just forward it!
        }
    }

    static class WithLimitingFilter implements Filterer {
        private final RateLimiter rateLimiter;

        public WithLimitingFilter(RateLimiter rateLimiter) {
            this.rateLimiter = rateLimiter;
        }

        @Override
        public String status() {
            return rateLimiter.status();
        }

        @Override
        public final void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {
            try {
                Limiter limiter = getLimiterWithLogging(request);
                if (limiter.shouldLimit()) {
                    limitRequest(request, response, "429 - Too Many Request - Request limited by Rate Limiter configuration: " + limiter.getLimitingKey().errorString());
                    return;
                }
            }
            catch (RuntimeException e) {
                log.error("Unexpected RateLimiter error w/ path '{}'", request.getRequestURI(), e);
            }
            filterChain.doFilter(request, response); // just forward it!
        }

        private Limiter getLimiterWithLogging(HttpServletRequest request) {
            Instant startTime = Instant.now();
            Limiter limiter = rateLimiter.checkRequest(request);
            if (limiter.shouldLimit() && log.isInfoEnabled()) {
                limiter.log(request.getRequestURI(), log::info, startTime);
            } else if (log.isDebugEnabled()) {
                limiter.log(request.getRequestURI(), log::debug, startTime);
            }
            return limiter;
        }

        private static void limitRequest(HttpServletRequest request, HttpServletResponse response, String error) throws IOException {
            request.setAttribute(RATE_LIMIT_ERROR_ATTRIBUTE, error);
            response.sendError(429, error);
        }
    }
}
