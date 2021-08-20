package org.cloudfoundry.identity.uaa.web;

import static org.mockito.ArgumentMatchers.isNotNull;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Random;

public class UaaLogFilterTest {
    private final UaaLogFilter logFilter = spy(new UaaLogFilter());

    @Test
    public void testLogFilterWithCorrelationIdHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String requestCorrelationId = Long.toHexString(new Random().nextLong());
        request.addHeader(UaaLogFilter.CORRELATION_HEADER_NAME, requestCorrelationId);
        logFilter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verify(logFilter).setCorrelationId(requestCorrelationId);
    }

    @Test
    public void testLogFilterWithoutCorrelationIdHeader() throws Exception {
        logFilter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain());

        verify(logFilter).setCorrelationId(isNotNull());
    }

    @Test
    public void testLogFilterWithEmptyCorrelationIdHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(UaaLogFilter.CORRELATION_HEADER_NAME, StringUtils.EMPTY);
        logFilter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verify(logFilter).setCorrelationId(isNotNull());
    }
}
