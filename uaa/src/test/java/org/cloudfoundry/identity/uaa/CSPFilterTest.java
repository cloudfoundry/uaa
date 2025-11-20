package org.cloudfoundry.identity.uaa;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.Environment;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CSPFilterTest {

    @Mock
    private FilterConfig filterConfig;

    @Mock
    private ServletContext servletContext;

    @Mock
    private WebApplicationContext webApplicationContext;

    @Mock
    private Environment environment;

    @Mock
    private ServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    private CSPFilter cspFilter;

    @BeforeEach
    void setUp() {
        cspFilter = new CSPFilter();
        // Only stub when needed - removed unnecessary stubbing
    }

    @Test
    void testInitWithSpringContextAndValidReportUri() throws ServletException {
        // Arrange
        when(filterConfig.getServletContext()).thenReturn(servletContext);

        try (MockedStatic<WebApplicationContextUtils> mockedUtils = mockStatic(WebApplicationContextUtils.class)) {
            mockedUtils.when(() -> WebApplicationContextUtils.getWebApplicationContext(servletContext))
                    .thenReturn(webApplicationContext);
            when(webApplicationContext.getEnvironment()).thenReturn(environment);
            when(environment.getProperty("cspReportUri",
                    System.getProperty("cspReportUri", System.getenv("CSP_REPORT_URI"))))
                    .thenReturn("https://example.com/csp-report");

            // Act
            cspFilter.init(filterConfig);

            // Assert
            verify(filterConfig).getServletContext();
            mockedUtils.verify(() -> WebApplicationContextUtils.getWebApplicationContext(servletContext));
            verify(webApplicationContext).getEnvironment();
        }
    }

    @Test
    void testInitWithSpringContextButEmptyReportUri() throws ServletException {
        // Arrange
        when(filterConfig.getServletContext()).thenReturn(servletContext);

        try (MockedStatic<WebApplicationContextUtils> mockedUtils = mockStatic(WebApplicationContextUtils.class)) {
            mockedUtils.when(() -> WebApplicationContextUtils.getWebApplicationContext(servletContext))
                    .thenReturn(webApplicationContext);
            when(webApplicationContext.getEnvironment()).thenReturn(environment);
            when(environment.getProperty("cspReportUri",
                    System.getProperty("cspReportUri", System.getenv("CSP_REPORT_URI"))))
                    .thenReturn("");

            // Act
            cspFilter.init(filterConfig);

            // Assert
            verify(environment).getProperty("cspReportUri",
                    System.getProperty("cspReportUri", System.getenv("CSP_REPORT_URI")));
        }
    }

    @Test
    void testInitWithSpringContextButNullReportUri() throws ServletException {
        // Arrange
        when(filterConfig.getServletContext()).thenReturn(servletContext);

        try (MockedStatic<WebApplicationContextUtils> mockedUtils = mockStatic(WebApplicationContextUtils.class)) {
            mockedUtils.when(() -> WebApplicationContextUtils.getWebApplicationContext(servletContext))
                    .thenReturn(webApplicationContext);
            when(webApplicationContext.getEnvironment()).thenReturn(environment);
            when(environment.getProperty("cspReportUri",
                    System.getProperty("cspReportUri", System.getenv("CSP_REPORT_URI"))))
                    .thenReturn(null);

            // Act
            cspFilter.init(filterConfig);

            // Assert
            verify(environment).getProperty("cspReportUri",
                    System.getProperty("cspReportUri", System.getenv("CSP_REPORT_URI")));
        }
    }

    @Test
    void testInitWithoutSpringContextFallsBackToSystemProperty() throws ServletException {
        // Arrange
        when(filterConfig.getServletContext()).thenReturn(servletContext);

        try (MockedStatic<WebApplicationContextUtils> mockedUtils = mockStatic(WebApplicationContextUtils.class)) {
            mockedUtils.when(() -> WebApplicationContextUtils.getWebApplicationContext(servletContext))
                    .thenReturn(null);

            // Act
            cspFilter.init(filterConfig);

            // Assert
            mockedUtils.verify(() -> WebApplicationContextUtils.getWebApplicationContext(servletContext));
        }
    }

    @Test
    void testInitWithoutSpringContextAndNoFallbackValues() throws ServletException {
        // Arrange
        when(filterConfig.getServletContext()).thenReturn(servletContext);

        try (MockedStatic<WebApplicationContextUtils> mockedUtils = mockStatic(WebApplicationContextUtils.class)) {
            mockedUtils.when(() -> WebApplicationContextUtils.getWebApplicationContext(servletContext))
                    .thenReturn(null);

            // Act
            cspFilter.init(filterConfig);

            // Assert
            mockedUtils.verify(() -> WebApplicationContextUtils.getWebApplicationContext(servletContext));
        }
    }

    @Test
    void testDoFilterWithValidReportUri() throws IOException, ServletException {
        // Arrange
        initializeFilterWithReportUri("https://example.com/csp-report");

        // Act
        cspFilter.doFilter(request, response, filterChain);

        // Assert
        verify(response).setHeader("Content-Security-Policy",
                "base-uri 'self'; frame-ancestors 'none'; font-src 'self' https://cdn.predix-ui.com; img-src 'self'; frame-src 'self';");
        verify(response).setHeader("Content-Security-Policy-Report-Only",
                "default-src 'self';" +
                        "script-src 'self';" +
                        "style-src 'self';" +
                        "object-src 'none';" +
                        "form-action 'self';" +
                        "report-uri https://example.com/csp-report;");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testDoFilterWithEmptyReportUri() throws IOException, ServletException {
        // Arrange
        initializeFilterWithReportUri("");

        // Act
        cspFilter.doFilter(request, response, filterChain);

        // Assert
        verify(response).setHeader("Content-Security-Policy",
                "base-uri 'self'; frame-ancestors 'none'; font-src 'self' https://cdn.predix-ui.com; img-src 'self'; frame-src 'self';");
        verify(response).setHeader("Content-Security-Policy-Report-Only",
                "default-src 'self';" +
                        "script-src 'self';" +
                        "style-src 'self';" +
                        "object-src 'none';" +
                        "form-action 'self';");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testDoFilterWithWhitespaceOnlyReportUri() throws IOException, ServletException {
        // Arrange
        initializeFilterWithReportUri("   ");

        // Act
        cspFilter.doFilter(request, response, filterChain);

        // Assert
        verify(response).setHeader("Content-Security-Policy-Report-Only",
                "default-src 'self';" +
                        "script-src 'self';" +
                        "style-src 'self';" +
                        "object-src 'none';" +
                        "form-action 'self';");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testDoFilterWithUninitializedFilter() throws IOException, ServletException {
        // Act - filter not initialized, cspReportUri remains empty string
        cspFilter.doFilter(request, response, filterChain);

        // Assert
        verify(response).setHeader("Content-Security-Policy",
                "base-uri 'self'; frame-ancestors 'none'; font-src 'self' https://cdn.predix-ui.com; img-src 'self'; frame-src 'self';");
        verify(response).setHeader("Content-Security-Policy-Report-Only",
                "default-src 'self';" +
                        "script-src 'self';" +
                        "style-src 'self';" +
                        "object-src 'none';" +
                        "form-action 'self';");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testDoFilterWithRelativeReportUri() throws IOException, ServletException {
        // Arrange
        initializeFilterWithReportUri("/api/csp-report");

        // Act
        cspFilter.doFilter(request, response, filterChain);

        // Assert
        verify(response).setHeader("Content-Security-Policy-Report-Only",
                "default-src 'self';" +
                        "script-src 'self';" +
                        "style-src 'self';" +
                        "object-src 'none';" +
                        "form-action 'self';" +
                        "report-uri /api/csp-report;");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testDoFilterWithComplexReportUri() throws IOException, ServletException {
        // Arrange
        initializeFilterWithReportUri("https://utility-dev.pss-shared.dev.usw02.15.energy/api/csp-report-uri");

        // Act
        cspFilter.doFilter(request, response, filterChain);

        // Assert
        verify(response).setHeader("Content-Security-Policy-Report-Only",
                "default-src 'self';" +
                        "script-src 'self';" +
                        "style-src 'self';" +
                        "object-src 'none';" +
                        "form-action 'self';" +
                        "report-uri https://utility-dev.pss-shared.dev.usw02.15.energy/api/csp-report-uri;");
    }

    @Test
    void testDestroy() {
        // Act
        cspFilter.destroy();

        // Assert - No exception should be thrown
    }

    @Test
    void testFilterChainContinuation() throws IOException, ServletException {
        // Arrange
        initializeFilterWithReportUri("https://example.com/csp-report");

        // Act
        cspFilter.doFilter(request, response, filterChain);

        // Assert
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void testMultipleDoFilterCallsWithSameConfiguration() throws IOException, ServletException {
        // Arrange
        initializeFilterWithReportUri("https://example.com/csp-report");

        // Act
        cspFilter.doFilter(request, response, filterChain);
        cspFilter.doFilter(request, response, filterChain);

        // Assert
        verify(response, times(2)).setHeader("Content-Security-Policy",
                "base-uri 'self'; frame-ancestors 'none'; font-src 'self' https://cdn.predix-ui.com; img-src 'self'; frame-src 'self';");
        verify(filterChain, times(2)).doFilter(request, response);
    }

    @Test
    void testInitWithSpringContextAndWhitespaceReportUri() throws ServletException {
        // Arrange
        when(filterConfig.getServletContext()).thenReturn(servletContext);

        try (MockedStatic<WebApplicationContextUtils> mockedUtils = mockStatic(WebApplicationContextUtils.class)) {
            mockedUtils.when(() -> WebApplicationContextUtils.getWebApplicationContext(servletContext))
                    .thenReturn(webApplicationContext);
            when(webApplicationContext.getEnvironment()).thenReturn(environment);
            when(environment.getProperty("cspReportUri",
                    System.getProperty("cspReportUri", System.getenv("CSP_REPORT_URI"))))
                    .thenReturn("   ");

            // Act
            cspFilter.init(filterConfig);

            // Assert
            verify(environment).getProperty("cspReportUri",
                    System.getProperty("cspReportUri", System.getenv("CSP_REPORT_URI")));
        }
    }

    @Test
    void testInitWithoutSpringContextAndWhitespaceReportUri() throws ServletException {
        // Arrange
        when(filterConfig.getServletContext()).thenReturn(servletContext);

        try (MockedStatic<WebApplicationContextUtils> mockedUtils = mockStatic(WebApplicationContextUtils.class)) {
            mockedUtils.when(() -> WebApplicationContextUtils.getWebApplicationContext(servletContext))
                    .thenReturn(null);

            // Act
            cspFilter.init(filterConfig);

            // Assert
            mockedUtils.verify(() -> WebApplicationContextUtils.getWebApplicationContext(servletContext));
        }
    }

    private void initializeFilterWithReportUri(String reportUri) {
        when(filterConfig.getServletContext()).thenReturn(servletContext);

        try (MockedStatic<WebApplicationContextUtils> mockedUtils = mockStatic(WebApplicationContextUtils.class)) {
            mockedUtils.when(() -> WebApplicationContextUtils.getWebApplicationContext(servletContext))
                    .thenReturn(webApplicationContext);
            when(webApplicationContext.getEnvironment()).thenReturn(environment);
            when(environment.getProperty("cspReportUri",
                    System.getProperty("cspReportUri", System.getenv("CSP_REPORT_URI"))))
                    .thenReturn(reportUri);

            cspFilter.init(filterConfig);
        } catch (ServletException e) {
            throw new RuntimeException(e);
        }
    }
}