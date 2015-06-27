package org.cloudfoundry.identity.uaa.web;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.internal.util.reflection.Whitebox.getInternalState;
import static org.mockito.internal.util.reflection.Whitebox.setInternalState;

import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.log4j.Appender;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.WriterAppender;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

public class CorsFilterTests {

    StringWriter writer;
    Appender appender;

    @Before
    public void start() {
        this.writer = new StringWriter();
        this.appender = new WriterAppender(new PatternLayout("%p, %m%n"), this.writer);
        this.writer.getBuffer().setLength(0);
        Logger.getRootLogger().addAppender(this.appender);
    }

    @After
    public void clean() {
        Logger.getRootLogger().removeAppender(this.appender);
    }

    @Test
    public void testRequestExpectStandardCorsResponse() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertEquals("*", response.getHeaderValue("Access-Control-Allow-Origin"));
    }

    @Test
    public void testRequestExpectXhrCorsResponse() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertEquals("example.com", response.getHeaderValue("Access-Control-Allow-Origin"));
    }

    @Test
    public void testRequestWithForbiddenOrigin() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "bunnyoutlet.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
    }

    @Test
    public void testRequestWithForbiddenUri() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/login");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
    }

    @Test
    public void testRequestWithMethodNotAllowed() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertEquals(405, response.getStatus());
    }

    @Test
    public void testPreFlightExpectStandardCorsResponse() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertStandardCorsPreFlightResponse(response);
    }

    @Test
    public void testPreFlightExpectXhrCorsResponse() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertXhrCorsPreFlightResponse(response);
    }

    @Test
    public void testPreFlightWrongOriginSpecified() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "bunnyoutlet.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
    }

    @Test
    public void testPreFlightRequestNoRequestMethod() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertEquals("example.com", response.getHeaderValue("Access-Control-Allow-Origin"));
    }

    @Test
    public void testPreFlightRequestMethodNotAllowed() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Access-Control-Request-Method", "POST");
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertEquals(405, response.getStatus());
    }

    @Test
    public void testPreFlightRequestHeaderNotAllowed() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With, X-Not-Allowed");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
    }

    @Test
    public void testPreFlightRequestUriNotWhitelisted() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/login");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "X-Requested-With");
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
    }

    @Test
    public void testPreFlightOriginNotWhitelisted() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "X-Requested-With");
        request.addHeader("Origin", "bunnyoutlet.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
    }

    @Test
    public void doInitializeWithNoPropertiesSet() throws ServletException, IOException {

        CorsFilter corsFilter = new CorsFilter();

        // We need to set the default value that Spring would otherwise set.
        List<String> allowedUris = new ArrayList<String>(Arrays.asList(new String[] { "^$" }));
        setInternalState(corsFilter, "corsXhrAllowedUris", allowedUris);

        // We need to set the default value that Spring would otherwise set.
        List<String> allowedOrigins = new ArrayList<String>(Arrays.asList(new String[] { "^$" }));
        setInternalState(corsFilter, "corsXhrAllowedOrigins", allowedOrigins);

        corsFilter.initialize();

        @SuppressWarnings("unchecked")
        List<Pattern> allowedUriPatterns = (List<Pattern>) getInternalState(corsFilter, "corsXhrAllowedUriPatterns");
        assertEquals(1, allowedUriPatterns.size());

        @SuppressWarnings("unchecked")
        List<Pattern> allowedOriginPatterns =
                (List<Pattern>) getInternalState(corsFilter, "corsXhrAllowedOriginPatterns");
        assertEquals(1, allowedOriginPatterns.size());

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertStandardCorsPreFlightResponse(response);
    }

    @Test
    public void doInitializeWithInvalidUriRegex() {

        CorsFilter corsFilter = new CorsFilter();

        List<String> allowedUris =
                new ArrayList<String>(Arrays.asList(new String[] { "^/uaa/userinfo(", "^/uaa/logout.do$" }));
        setInternalState(corsFilter, "corsXhrAllowedUris", allowedUris);

        List<String> allowedOrigins = new ArrayList<String>(Arrays.asList(new String[] { "example.com$" }));
        setInternalState(corsFilter, "corsXhrAllowedOrigins", allowedOrigins);

        corsFilter.initialize();

        assertTrue("Did not find expected error message in log.",
                this.writer.toString().contains("Invalid regular expression pattern in cors.xhr.allowed.uris:"));
    }

    @Test
    public void doInitializeWithInvalidOriginRegex() {

        CorsFilter corsFilter = new CorsFilter();

        List<String> allowedUris =
                new ArrayList<String>(Arrays.asList(new String[] { "^/uaa/userinfo$", "^/uaa/logout.do$" }));
        setInternalState(corsFilter, "corsXhrAllowedUris", allowedUris);

        List<String> allowedOrigins = new ArrayList<String>(Arrays.asList(new String[] { "example.com(" }));
        setInternalState(corsFilter, "corsXhrAllowedOrigins", allowedOrigins);

        corsFilter.initialize();

        assertTrue("Did not find expected error message in log.",
                this.writer.toString().contains("Invalid regular expression pattern in cors.xhr.allowed.origins:"));
    }

    private static CorsFilter createConfiguredCorsFilter() {
        CorsFilter corsFilter = new CorsFilter();

        List<String> allowedUris =
                new ArrayList<String>(Arrays.asList(new String[] { "^/uaa/userinfo$", "^/uaa/logout\\.do$" }));
        setInternalState(corsFilter, "corsXhrAllowedUris", allowedUris);

        List<String> allowedOrigins = new ArrayList<String>(Arrays.asList(new String[] { "example.com$" }));
        setInternalState(corsFilter, "corsXhrAllowedOrigins", allowedOrigins);

        corsFilter.initialize();
        return corsFilter;
    }

    private static void assertStandardCorsPreFlightResponse(final MockHttpServletResponse response) {
        assertEquals("*", response.getHeaderValue("Access-Control-Allow-Origin"));
        assertEquals("GET, POST, PUT, DELETE", response.getHeaderValue("Access-Control-Allow-Methods"));
        assertEquals("Authorization", response.getHeaderValue("Access-Control-Allow-Headers"));
        assertEquals("1728000", response.getHeaderValue("Access-Control-Max-Age"));
    }

    private static void assertXhrCorsPreFlightResponse(final MockHttpServletResponse response) {
        assertEquals("example.com", response.getHeaderValue("Access-Control-Allow-Origin"));
        assertEquals("GET", response.getHeaderValue("Access-Control-Allow-Methods"));
        assertEquals("Authorization, X-Requested-With", response.getHeaderValue("Access-Control-Allow-Headers"));
        assertEquals("1728000", response.getHeaderValue("Access-Control-Max-Age"));
    }

    private static FilterChain newMockFilterChain() {
        FilterChain filterChain = new FilterChain() {

            @Override
            public void doFilter(final ServletRequest request, final ServletResponse response)
                    throws IOException,
                    ServletException {
                // Do nothing.
            }
        };
        return filterChain;
    }

}
