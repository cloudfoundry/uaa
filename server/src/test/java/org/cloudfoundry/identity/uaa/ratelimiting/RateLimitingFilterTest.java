package org.cloudfoundry.identity.uaa.ratelimiting;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

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

        verify(limiterInstance).shouldLimit();
        verify(response, times(0)).sendError(eq(429), anyString());
    }

    @Test
    void withConfigLimitsWith429() throws ServletException, IOException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        Limiter limiterInstance = mock(Limiter.class);
        when(limiterInstance.shouldLimit()).thenReturn(true);
        when(limiter.checkRequest(request)).thenReturn(limiterInstance);

        instance.doFilter(request, response, chain);

        verify(limiterInstance).shouldLimit();
        verify(response).sendError(eq(429), anyString());
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

        verify(chain, times(0)).doFilter(any(), any());
        verify(writer).close();
        verify(response).setStatus(200);
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

        verify(chain, times(0)).doFilter(any(), any());
        verify(writer).close();
        verify(response).setStatus(200);
    }
}
