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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.ACCEPT_LANGUAGE;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_LANGUAGE;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

class CorsFilterDefaultZoneTests {
    private final List<String> logEvents = new ArrayList<>();
    private AbstractAppender appender;
    IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);

    @BeforeEach
    void setUp() {
        appender = new AbstractAppender("", null, null) {
            @Override
            public void append(LogEvent event) {
                logEvents.add(event.getMessage().getFormattedMessage());
            }
        };
        appender.start();

        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        context.getRootLogger().addAppender(appender);

        when(mockIdentityZoneManager.isCurrentZoneUaa()).thenReturn(true);
    }

    @AfterEach
    void removeAppender() {
        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        context.getRootLogger().removeAppender(appender);
    }

    @Test
    void xhr_default_allowed_methods() {
        CorsFilter filter = new CorsFilter(mockIdentityZoneManager, false);
        assertThat(filter.getXhrConfiguration().getAllowedMethods()).containsExactlyInAnyOrder("GET", "OPTIONS");
    }

    @Test
    void non_xhr_default_allowed_methods() {
        CorsFilter filter = new CorsFilter(mockIdentityZoneManager, false);
        assertThat(filter.getDefaultConfiguration().getAllowedMethods()).containsExactlyInAnyOrder("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH");
    }

    @Test
    void xhr_default_allowed_headers() {
        CorsFilter filter = new CorsFilter(mockIdentityZoneManager, false);
        assertThat(filter.getXhrConfiguration().getAllowedHeaders()).containsExactlyInAnyOrder(ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, CONTENT_LANGUAGE, AUTHORIZATION, CorsFilter.X_REQUESTED_WITH);
    }

    @Test
    void non_xhr_default_allowed_headers() {
        CorsFilter filter = new CorsFilter(mockIdentityZoneManager, false);
        assertThat(filter.getDefaultConfiguration().getAllowedHeaders()).containsExactlyInAnyOrder(ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, CONTENT_LANGUAGE, AUTHORIZATION);
    }

    @Test
    void xhr_default_allowed_credentials() {
        CorsFilter filter = new CorsFilter(mockIdentityZoneManager, false);
        assertThat(filter.getXhrConfiguration().isAllowedCredentials()).isTrue();
    }

    @Test
    void non_xhr_default_allowed_credentials() {
        CorsFilter filter = new CorsFilter(mockIdentityZoneManager, false);
        assertThat(filter.getDefaultConfiguration().isAllowedCredentials()).isFalse();
    }

    @Test
    void requestExpectStandardCorsResponse() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("*");
    }

    @Test
    void requestWithMaliciousOrigin() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "<script>alert('1ee7 h@x0r')</script>");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void requestExpectXhrCorsResponse() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("example.com");
    }

    @Test
    void sameOriginRequest() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void requestWithForbiddenOrigin() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "bunnyoutlet.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void requestWithForbiddenUri() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/login");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void requestWithMethodNotAllowed() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(405);
    }

    @Test
    void preFlightExpectStandardCorsResponse() throws ServletException, IOException {
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
    void preFlightExpectXhrCorsResponse() throws ServletException, IOException {
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
    void preFlightWrongOriginSpecified() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "bunnyoutlet.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void preFlightRequestNoRequestMethod() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("example.com");
    }

    @Test
    void preFlightRequestMethodNotAllowed() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Access-Control-Request-Method", "POST");
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(405);
    }

    @Test
    void preFlightRequestHeaderNotAllowed() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With, X-Not-Allowed");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void preFlightRequestUriNotWhitelisted() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/login");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "X-Requested-With");
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void preFlightOriginNotWhitelisted() throws ServletException, IOException {
        CorsFilter corsFilter = createConfiguredCorsFilter();

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "X-Requested-With");
        request.addHeader("Origin", "bunnyoutlet.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void doInitializeWithNoPropertiesSet() throws ServletException, IOException {

        CorsFilter corsFilter = new CorsFilter(mockIdentityZoneManager, false);

        // We need to set the default value that Spring would otherwise set.
        List<String> allowedUris = new ArrayList<>(Collections.singletonList(".*"));
        corsFilter.getXhrConfiguration().setAllowedUris(allowedUris);
        corsFilter.getDefaultConfiguration().setAllowedUris(allowedUris);

        // We need to set the default value that Spring would otherwise set.
        List<String> allowedOrigins = new ArrayList<>(Collections.singletonList(".*"));
        corsFilter.getDefaultConfiguration().setAllowedOrigins(allowedOrigins);

        corsFilter.initialize();

        List<Pattern> allowedUriPatterns = corsFilter.getXhrConfiguration().getAllowedUriPatterns();
        assertThat(allowedUriPatterns).hasSize(1);

        List<Pattern> allowedOriginPatterns = corsFilter.getXhrConfiguration().getAllowedOriginPatterns();
        assertThat(allowedOriginPatterns).hasSize(1);

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", AUTHORIZATION + ", " + ACCEPT + ", " + CONTENT_TYPE + ", " + ACCEPT_LANGUAGE + ", " + CONTENT_LANGUAGE);
        request.addHeader("Origin", "example.com");

        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain filterChain = newMockFilterChain();

        corsFilter.doFilter(request, response, filterChain);

        assertStandardCorsPreFlightResponse(response, "GET, OPTIONS, POST, PUT, DELETE, PATCH", AUTHORIZATION, ACCEPT, CONTENT_TYPE, ACCEPT_LANGUAGE, CONTENT_LANGUAGE);
    }

    @Test
    void doInitializeWithInvalidUriRegex() {

        CorsFilter corsFilter = new CorsFilter(mockIdentityZoneManager, false);

        List<String> allowedUris =
                new ArrayList<>(Arrays.asList(new String[]{"^/uaa/userinfo(", "^/uaa/logout.do$"}));
        corsFilter.getXhrConfiguration().setAllowedUris(allowedUris);

        List<String> allowedOrigins = new ArrayList<>(Arrays.asList(new String[]{"example.com$"}));
        corsFilter.getXhrConfiguration().setAllowedOrigins(allowedOrigins);

        corsFilter.initialize();

        assertThat(logEvents).anySatisfy(l -> assertThat(l).startsWith("Invalid regular expression pattern in cors.xhr.allowed.uris:"));
    }

    @Test
    void doInitializeWithInvalidOriginRegex() {

        CorsFilter corsFilter = new CorsFilter(mockIdentityZoneManager, false);

        List<String> allowedUris = new ArrayList<>(Arrays.asList("^/uaa/userinfo$", "^/uaa/logout.do$"));
        corsFilter.getXhrConfiguration().setAllowedUris(allowedUris);

        List<String> allowedOrigins = new ArrayList<>(Collections.singletonList("example.com("));
        corsFilter.getXhrConfiguration().setAllowedOrigins(allowedOrigins);

        corsFilter.initialize();

        assertThat(logEvents.stream().anyMatch(logMsg -> logMsg.contains("Invalid regular expression pattern in cors.xhr.allowed.origins:"))).as("Did not find expected error message in log.").isTrue();
    }

    private CorsFilter createConfiguredCorsFilter() {
        CorsFilter corsFilter = new CorsFilter(mockIdentityZoneManager, false);

        List<String> allowedUris = new ArrayList<>(Arrays.asList("^/uaa/userinfo$", "^/uaa/logout\\.do$"));
        corsFilter.getXhrConfiguration().setAllowedUris(allowedUris);
        corsFilter.getDefaultConfiguration().setAllowedUris(allowedUris);

        List<String> allowedOrigins = new ArrayList<>(Collections.singletonList("example.com$"));
        corsFilter.getXhrConfiguration().setAllowedOrigins(allowedOrigins);
        corsFilter.getDefaultConfiguration().setAllowedOrigins(allowedOrigins);

        corsFilter.getXhrConfiguration().setAllowedHeaders(Arrays.asList("Accept", "Authorization", "X-Requested-With"));
        corsFilter.getDefaultConfiguration().setAllowedHeaders(Arrays.asList("Accept", "Authorization"));

        corsFilter.initialize();
        return corsFilter;
    }

    private void assertStandardCorsPreFlightResponse(final MockHttpServletResponse response, String allowedMethods, String... allowedHeaders) {
        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("*");
        assertThat(response.getHeaderValue("Access-Control-Allow-Methods")).isEqualTo(allowedMethods);
        assertThat(new CorsFilter(mockIdentityZoneManager, false).splitCommaDelimitedString((String) response.getHeaderValue("Access-Control-Allow-Headers"))).containsExactlyInAnyOrder(allowedHeaders);
        assertThat(response.getHeaderValue("Access-Control-Max-Age")).isEqualTo("1728000");
    }

    private static void assertXhrCorsPreFlightResponse(final MockHttpServletResponse response) {
        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("example.com");
        assertThat(response.getHeaderValue("Access-Control-Allow-Methods")).isEqualTo("GET, POST, PUT, DELETE");
        assertThat(response.getHeaderValue("Access-Control-Allow-Headers")).isEqualTo("Authorization, X-Requested-With");
        assertThat(response.getHeaderValue("Access-Control-Max-Age")).isEqualTo("1728000");
    }

    private static FilterChain newMockFilterChain() {
        return (request, response) -> {
            // Do nothing.
        };
    }

}
