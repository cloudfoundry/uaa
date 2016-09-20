/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.security.web;

import org.apache.log4j.Appender;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.WriterAppender;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.ACCEPT_LANGUAGE;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_LANGUAGE;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

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
    public void test_XHR_Default_Allowed_Methods() {
        CorsFilter filter = new CorsFilter();
        assertThat(filter.getXhrConfiguration().getAllowedMethods(), containsInAnyOrder("GET", "OPTIONS"));
    }

    @Test
    public void test_NonXHR_Default_Allowed_Methods() {
        CorsFilter filter = new CorsFilter();
        assertThat(filter.getDefaultConfiguration().getAllowedMethods(), containsInAnyOrder("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
    }

    @Test
    public void test_XHR_Default_Allowed_Headers() {
        CorsFilter filter = new CorsFilter();
        assertThat(filter.getXhrConfiguration().getAllowedHeaders(), containsInAnyOrder(ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, CONTENT_LANGUAGE,AUTHORIZATION, CorsFilter.X_REQUESTED_WITH));
    }

    @Test
    public void test_NonXHR_Default_Allowed_Headers() {
        CorsFilter filter = new CorsFilter();
        assertThat(filter.getDefaultConfiguration().getAllowedHeaders(), containsInAnyOrder(ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, CONTENT_LANGUAGE,AUTHORIZATION));
    }

    @Test
    public void test_XHR_Default_Allowed_Credentials() {
        CorsFilter filter = new CorsFilter();
        assertTrue(filter.getXhrConfiguration().isAllowedCredentials());
    }

    @Test
    public void test_NonXHR_Default_Allowed_Credentials() {
        CorsFilter filter = new CorsFilter();
        assertFalse(filter.getDefaultConfiguration().isAllowedCredentials());
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
    public void testRequestWithMaliciousOrigin() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "<script>alert('1ee7 h@x0r')</script>");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
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
    public void testSameOriginRequest() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertEquals(200, response.getStatus());
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
        corsFilter.getDefaultConfiguration().setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertStandardCorsPreFlightResponse(response, "GET, POST, PUT, DELETE", "Authorization");
    }

    @Test
    public void testPreFlightExpectXhrCorsResponse() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();
        corsFilter.getXhrConfiguration().setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
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
        List<String> allowedUris = new ArrayList<>(Arrays.asList(".*"));
        corsFilter.getXhrConfiguration().setAllowedUris(allowedUris);
        corsFilter.getDefaultConfiguration().setAllowedUris(allowedUris);

        // We need to set the default value that Spring would otherwise set.
        List<String> allowedOrigins = new ArrayList<>(Arrays.asList(".*"));
        corsFilter.getDefaultConfiguration().setAllowedOrigins(allowedOrigins);

        corsFilter.initialize();

        @SuppressWarnings("unchecked")
        List<Pattern> allowedUriPatterns = corsFilter.getXhrConfiguration().getAllowedUriPatterns();
        assertEquals(1, allowedUriPatterns.size());

        @SuppressWarnings("unchecked")
        List<Pattern> allowedOriginPatterns = corsFilter.getXhrConfiguration().getAllowedOriginPatterns();
        assertEquals(1, allowedOriginPatterns.size());

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", AUTHORIZATION+", "+ACCEPT+", "+CONTENT_TYPE+", "+ACCEPT_LANGUAGE+", "+CONTENT_LANGUAGE);
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertStandardCorsPreFlightResponse(response, "GET, OPTIONS, POST, PUT, DELETE, PATCH", AUTHORIZATION, ACCEPT, CONTENT_TYPE, ACCEPT_LANGUAGE, CONTENT_LANGUAGE);
    }

    @Test
    public void doInitializeWithInvalidUriRegex() {

        CorsFilter corsFilter = new CorsFilter();

        List<String> allowedUris =
                new ArrayList<String>(Arrays.asList(new String[] { "^/uaa/userinfo(", "^/uaa/logout.do$" }));
        corsFilter.getXhrConfiguration().setAllowedUris(allowedUris);

        List<String> allowedOrigins = new ArrayList<String>(Arrays.asList(new String[] { "example.com$" }));
        corsFilter.getXhrConfiguration().setAllowedOrigins(allowedOrigins);

        corsFilter.initialize();

        assertTrue("Did not find expected error message in log.",
                this.writer.toString().contains("Invalid regular expression pattern in cors.xhr.allowed.uris:"));
    }

    @Test
    public void doInitializeWithInvalidOriginRegex() {

        CorsFilter corsFilter = new CorsFilter();

        List<String> allowedUris = new ArrayList<>(Arrays.asList("^/uaa/userinfo$", "^/uaa/logout.do$"));
        corsFilter.getXhrConfiguration().setAllowedUris(allowedUris);

        List<String> allowedOrigins = new ArrayList<>(Arrays.asList("example.com("));
        corsFilter.getXhrConfiguration().setAllowedOrigins(allowedOrigins);

        corsFilter.initialize();

        assertTrue("Did not find expected error message in log.",
                this.writer.toString().contains("Invalid regular expression pattern in cors.xhr.allowed.origins:"));
    }

    private static CorsFilter createConfiguredCorsFilter() {
        CorsFilter corsFilter = new CorsFilter();

        List<String> allowedUris = new ArrayList<>(Arrays.asList("^/uaa/userinfo$", "^/uaa/logout\\.do$" ));
        corsFilter.getXhrConfiguration().setAllowedUris(allowedUris);
        corsFilter.getDefaultConfiguration().setAllowedUris(allowedUris);

        List<String> allowedOrigins = new ArrayList<String>(Arrays.asList("example.com$"));
        corsFilter.getXhrConfiguration().setAllowedOrigins(allowedOrigins);
        corsFilter.getDefaultConfiguration().setAllowedOrigins(allowedOrigins);

        corsFilter.getXhrConfiguration().setAllowedHeaders(Arrays.asList("Accept", "Authorization","X-Requested-With"));
        corsFilter.getDefaultConfiguration().setAllowedHeaders(Arrays.asList("Accept", "Authorization"));

        corsFilter.initialize();
        return corsFilter;
    }

    private static void assertStandardCorsPreFlightResponse(final MockHttpServletResponse response, String allowedMethods, String... allowedHeaders) {
        assertEquals("*", response.getHeaderValue("Access-Control-Allow-Origin"));
        assertEquals(allowedMethods, response.getHeaderValue("Access-Control-Allow-Methods"));
        assertThat(new CorsFilter().splitCommaDelimitedString((String)response.getHeaderValue("Access-Control-Allow-Headers")), containsInAnyOrder(allowedHeaders));
        assertEquals("1728000", response.getHeaderValue("Access-Control-Max-Age"));
    }

    private static void assertXhrCorsPreFlightResponse(final MockHttpServletResponse response) {
        assertEquals("example.com", response.getHeaderValue("Access-Control-Allow-Origin"));
        assertEquals("GET, POST, PUT, DELETE", response.getHeaderValue("Access-Control-Allow-Methods"));
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
