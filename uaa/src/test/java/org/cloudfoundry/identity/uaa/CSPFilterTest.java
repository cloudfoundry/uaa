package org.cloudfoundry.identity.uaa;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.web.context.ConfigurableWebApplicationContext;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.*;

public class CSPFilterTest {

    private CSPFilter cspFilter;

    @Mock
    private ConfigurableWebApplicationContext applicationContext;

    @Mock
    private ConfigurableEnvironment environment;

    @Mock
    private FilterConfig filterConfig;

    @Mock
    private ServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        cspFilter = new CSPFilter();
        when(applicationContext.getEnvironment()).thenReturn(environment);
    }

    @Test
    public void testInitialize_WithValidCspReportUri() {
        when(environment.getProperty("cspReportUri")).thenReturn("/test-report-uri");

        cspFilter.initialize(applicationContext);

        verify(environment).getProperty("cspReportUri");
    }

    @Test
    public void testInitialize_WithEmptyCspReportUri() {
        when(environment.getProperty("cspReportUri")).thenReturn("");

        cspFilter.initialize(applicationContext);

        verify(environment).getProperty("cspReportUri");
    }

    @Test
    public void testInitialize_WithNullCspReportUri() {
        when(environment.getProperty("cspReportUri")).thenReturn(null);

        cspFilter.initialize(applicationContext);

        verify(environment).getProperty("cspReportUri");
    }

    @Test
    public void testDoFilter_SetsCSPHeaders() throws Exception {
        cspFilter.doFilter(request, response, filterChain);

        verify(response).setHeader("Content-Security-Policy",
                "base-uri 'self'; frame-ancestors 'none'; font-src 'self' https://cdn.predix-ui.com; img-src 'self'; frame-src 'self';");

        verify(response).setHeader("Content-Security-Policy-Report-Only",
                "default-src 'self';script-src 'self';style-src 'self';object-src 'none';form-action 'self';report-uri ;");

        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void testDoFilter_WithConfiguredReportUri() throws Exception {
        when(environment.getProperty("cspReportUri")).thenReturn("/custom-report-uri");
        cspFilter.initialize(applicationContext);

        cspFilter.doFilter(request, response, filterChain);

        verify(response).setHeader("Content-Security-Policy-Report-Only",
                "default-src 'self';script-src 'self';style-src 'self';object-src 'none';form-action 'self';report-uri /custom-report-uri;");

        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void testInit_DoesNotThrowException() throws Exception {
        cspFilter.init(filterConfig);
        // Test passes if no exception is thrown
    }

    @Test
    public void testDestroy_DoesNotThrowException() {
        cspFilter.destroy();
        // Test passes if no exception is thrown
    }
}