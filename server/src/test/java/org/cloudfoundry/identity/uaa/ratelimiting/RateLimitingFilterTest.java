package org.cloudfoundry.identity.uaa.ratelimiting;

import static org.cloudfoundry.identity.uaa.ratelimiting.RateLimitingFilter.RATE_LIMIT_ERROR_ATTRIBUTE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.Limiter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.RateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RateLimitingFilterTest {

    private RateLimitingFilter instanceNoConfig;
    private RateLimitingFilter instance;
    private RateLimiter limiter;

    @BeforeEach
    void setUp() throws ServletException {
        instanceNoConfig = new RateLimitingFilter();
        limiter = mock(RateLimiter.class);
        instance = new RateLimitingFilter(limiter);
    }

    @Test
    void inactiveByDefault() throws ServletException, IOException {
        instanceNoConfig.doFilter(mock(HttpServletRequest.class), mock(HttpServletResponse.class), mock(FilterChain.class));

        verify(limiter, times(0)).checkRequest(any());
    }

    @Test
    void withConfigActive() throws ServletException, IOException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        Limiter limiterInstance = mock(Limiter.class);
        when(limiterInstance.shouldLimit()).thenReturn(false);
        when(limiter.checkRequest(request)).thenReturn(limiterInstance);

        instance.doFilter(request, response, chain);

        verify(limiterInstance, times(2)).shouldLimit();
        verify(response, times(0)).sendError(eq(429), anyString());
    }

    @Test
    void withConfigLimitsWith429() throws ServletException, IOException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        Limiter limiterInstance = mock(Limiter.class);
        CompoundKey compoundKey = mock(CompoundKey.class);
        when(compoundKey.errorString()).thenReturn("LIMITED");
        when(limiterInstance.getLimitingKey()).thenReturn(compoundKey);
        when(limiterInstance.shouldLimit()).thenReturn(true);
        when(limiter.checkRequest(request)).thenReturn(limiterInstance);

        instance.doFilter(request, response, chain);

        verify(limiterInstance, times(2)).shouldLimit();
        verify(request).setAttribute(eq(RATE_LIMIT_ERROR_ATTRIBUTE), contains("LIMITED"));
        verify(response).sendError(eq(429), contains("LIMITED"));
    }

    @Test
    void statusReturnsWithoutFurtherProcessing() throws ServletException, IOException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServletPath()).thenReturn("/RateLimitingStatus");
        HttpServletResponse response = mock(HttpServletResponse.class);
        PrintWriter writer = mock(PrintWriter.class);
        when(response.getWriter()).thenReturn(writer);
        FilterChain chain = mock(FilterChain.class);

        instance.doFilter(request, response, chain);

        verify(chain, times(1)).doFilter(any(), any());
    }

    @Test
    void statusReturnsWithoutFurtherProcessingNoConfig() throws ServletException, IOException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServletPath()).thenReturn("/RateLimitingStatus");
        HttpServletResponse response = mock(HttpServletResponse.class);
        PrintWriter writer = mock(PrintWriter.class);
        when(response.getWriter()).thenReturn(writer);
        FilterChain chain = mock(FilterChain.class);

        instanceNoConfig.doFilter(request, response, chain);

        verify(chain, times(1)).doFilter(any(), any());
    }
}
