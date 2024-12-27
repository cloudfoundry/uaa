package org.cloudfoundry.identity.uaa.security.web;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpMethod.*;
import static org.springframework.http.HttpStatus.*;

class CorsFilterNonDefaultZoneTests {
    private IdentityZoneManager mockIdentityZoneManager;
    private IdentityZone identityZone;
    private FilterChain filterChain;
    private CorsFilter corsFilter;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        // Make our target current zone as non-default zone
        when(mockIdentityZoneManager.isCurrentZoneUaa()).thenReturn(false);
        identityZone = new IdentityZone();
        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(identityZone);
        corsFilter = new CorsFilter(mockIdentityZoneManager, false);

        filterChain = newMockFilterChain();

        response = new MockHttpServletResponse();

        setupBaselineCorsPolicyXhrConfiguration();
        setupBaselineCorsPolicyDefaultConfiguration();
    }

    // Xhr cors
    @ParameterizedTest
    @CsvSource({
            "GET, /uaa/userinfo, <script>alert('1ee7 h@x0r')</script>, Invalid origin",
            "GET, /uaa/userinfo, bunnyoutlet.com, Illegal origin",
            "GET, /uaa/login, example.com, Illegal request URI",
    })
    void testRequestWithInvalidOrigins(String method, String url, String origin, String message) throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest(method, url);
        request.addHeader("Origin", origin);
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(FORBIDDEN.value(), response.getStatus());
        assertEquals(message, response.getErrorMessage());
    }

    @Test
    void testSameOriginRequest() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(OK.value(), response.getStatus());
    }

    // happy path
    @Test
    void testRequestExpectXhrCorsResponse() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(OK.value(), response.getStatus());
        assertEquals("example.com", response.getHeaderValue("Access-Control-Allow-Origin"));
    }

    @Test
    void testRequestWithAllowedOriginPatterns() throws ServletException, IOException {
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().getAllowedOriginPatterns()
                .add(Pattern.compile("bunnyoutlet-shop.com$"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "bunnyoutlet-shop.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(OK.value(), response.getStatus());
    }

    @Test
    void testRequestWithAllowedUriPatterns() throws ServletException, IOException {
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().getAllowedUriPatterns()
                .add(Pattern.compile("/uaa/*"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/login");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(OK.value(), response.getStatus());
    }

    @Test
    void testRequestWithMethodNotAllowed() throws ServletException, IOException {
        List<String> allowedMethods = List.of(GET.toString(), OPTIONS.toString(), DELETE.toString());
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().setAllowedMethods(allowedMethods);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(METHOD_NOT_ALLOWED.value(), response.getStatus());
        assertEquals("Illegal method.", response.getErrorMessage());
    }

    // preflight happy path
    @Test
    void testPreFlightExpectXhrCorsResponse() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals("example.com", response.getHeaderValue("Access-Control-Allow-Origin"));
        assertEquals("GET, POST, PUT, DELETE",
                response.getHeaderValue("Access-Control-Allow-Methods"));
        assertEquals("Authorization, X-Requested-With",
                response.getHeaderValue("Access-Control-Allow-Headers"));
        assertEquals("187000", response.getHeaderValue("Access-Control-Max-Age"));
        assertEquals(OK.value(), response.getStatus());
    }

    @Test
    void testPreFlightWrongOriginSpecified() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "bunnyoutlet.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
        assertEquals("Illegal origin", response.getErrorMessage());
    }

    @Test
    void testPreFlightRequestNoRequestMethod() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(400, response.getStatus());
        assertEquals("Access-Control-Request-Method header is missing", response.getErrorMessage());
        assertEquals("example.com", response.getHeaderValue("Access-Control-Allow-Origin"));
    }

    @Test
    void testPreFlightRequestMethodNotAllowed() throws ServletException, IOException {
        List<String> allowedMethods = List.of(GET.toString(), PUT.toString(), DELETE.toString());
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().setAllowedMethods(allowedMethods);

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Access-Control-Request-Method", "POST");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(405, response.getStatus());
        assertEquals("Illegal method requested", response.getErrorMessage());
    }

    @Test
    void testPreFlightRequestHeaderNotAllowed() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With, X-Not-Allowed");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
        assertEquals("Illegal header requested", response.getErrorMessage());
    }

    @Test
    void testPreFlightRequestUriNotAllowed() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/login");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "X-Requested-With");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
        assertEquals("Illegal request URI", response.getErrorMessage());
    }

    @Test
    void testPreFlightOriginNotAllowed() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "X-Requested-With");
        request.addHeader("Origin", "bunnyoutlet.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
        assertEquals("Illegal origin", response.getErrorMessage());
    }

    // default cors
    @ParameterizedTest
    @CsvSource({
            "GET, /uaa/userinfo, <script>alert('1ee7 h@x0r')</script>, Invalid origin",
            "GET, /uaa/userinfo, bunnyoutlet.com, Illegal origin",
            "GET, /uaa/login, example.com, Illegal request URI",
    })
    void testDefaultCorsWithInvalidOrigins(String method, String url, String origin, String message) throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest(method, url);
        request.addHeader("Origin", origin);
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(FORBIDDEN.value(), response.getStatus());
        assertEquals(message, response.getErrorMessage());
    }

    @Test
    void testDefaultCorsWithSameOrigin() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(OK.value(), response.getStatus());
    }

    // happy path
    @Test
    void testDefaultCorsExpectStandardCorsResponse() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(OK.value(), response.getStatus());
        assertEquals("example.com", response.getHeaderValue("Access-Control-Allow-Origin"));
    }

    @Test
    void testDefaultCorsWithAllowedOriginPatterns() throws ServletException, IOException {
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().getAllowedOriginPatterns()
                .add(Pattern.compile("bunnyoutlet.com$"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "bunnyoutlet.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(OK.value(), response.getStatus());
    }

    @Test
    void testDefaultCorsWithAllowedUriPatterns() throws ServletException, IOException {
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().getAllowedUriPatterns()
                .add(Pattern.compile("/uaa/*"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/login");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(OK.value(), response.getStatus());
    }

    @Test
    void testDefaultCorsWithMethodNotAllowed() throws ServletException, IOException {
        List<String> allowedMethods = List.of(GET.toString(), OPTIONS.toString(), DELETE.toString());
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().setAllowedMethods(allowedMethods);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(METHOD_NOT_ALLOWED.value(), response.getStatus());
        assertEquals("Illegal method.", response.getErrorMessage());
    }

    // preflight happy path
    @Test
    void testDefaultCorsPreFlightExpectStandardCorsResponse() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals("example.com", response.getHeaderValue("Access-Control-Allow-Origin"));
        assertEquals("GET, POST, PUT, DELETE", response.getHeaderValue("Access-Control-Allow-Methods"));
        MatcherAssert.assertThat(new CorsFilter(mockIdentityZoneManager, false).
                splitCommaDelimitedString((String) response.getHeaderValue("Access-Control-Allow-Headers")), containsInAnyOrder("Authorization"));
        assertEquals("187000", response.getHeaderValue("Access-Control-Max-Age"));
    }

    @Test
    void testDefaultCorsPreFlightWrongOriginSpecified() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "bunnyoutlet.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
        assertEquals("Illegal origin", response.getErrorMessage());
    }

    @Test
    void testDefaultCorsPreFlightRequestNoRequestMethod() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(400, response.getStatus());
        assertEquals("Access-Control-Request-Method header is missing", response.getErrorMessage());
        assertEquals("example.com", response.getHeaderValue("Access-Control-Allow-Origin"));
    }

    @Test
    void testDefaultCorsPreFlightRequestMethodNotAllowed() throws ServletException, IOException {
        List<String> allowedMethods = List.of(GET.toString(), PUT.toString(), DELETE.toString());
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().setAllowedMethods(allowedMethods);

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Access-Control-Request-Method", "POST");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(405, response.getStatus());
        assertEquals("Illegal method requested", response.getErrorMessage());
    }

    @Test
    void testDefaultCorsPreFlightRequestHeaderNotAllowed() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Not-Allowed");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
        assertEquals("Illegal header requested", response.getErrorMessage());
    }

    @Test
    void testDefaultCorsPreFlightRequestUriNotAllowed() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/login");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
        assertEquals("Illegal request URI", response.getErrorMessage());
    }

    @Test
    void testDefaultCorsPreFlightOriginNotAllowed() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Origin", "bunnyoutlet.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(403, response.getStatus());
        assertEquals("Illegal origin", response.getErrorMessage());
    }

    @Test
    void testRequestWithAllowedOriginPatternsEnforcingSystemZonePolicy() throws ServletException, IOException {
        CorsFilter corsFilter = new CorsFilter(mockIdentityZoneManager, true);
        corsFilter.setCorsXhrAllowedOrigins(List.of("example.com"));
        corsFilter.initialize();

        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().getAllowedOriginPatterns()
                .add(Pattern.compile("bunnyoutlet-shop.com$"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "bunnyoutlet-shop.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(FORBIDDEN.value(), response.getStatus());
        assertEquals("Illegal origin", response.getErrorMessage());
    }

    @Test
    void testDefaultCorsPreFlightRequestMethodNotAllowedEnforcingSystemZonePolicy() throws ServletException, IOException {
        CorsFilter corsFilter = new CorsFilter(mockIdentityZoneManager, true);
        corsFilter.setCorsAllowedMethods(List.of(GET.toString(), PUT.toString(), DELETE.toString()));
        corsFilter.initialize();

        List<String> allowedMethods = List.of(GET.toString());
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().setAllowedMethods(allowedMethods);

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Access-Control-Request-Method", "PUT");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertEquals(OK.value(), response.getStatus());
    }

    private void setupBaselineCorsPolicyXhrConfiguration() {
        List<String> allowedMethods = List.of(GET.toString(), POST.toString(),
                PUT.toString(), DELETE.toString());
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().setAllowedMethods(allowedMethods);

        List<String> allowedUris = new ArrayList<>(Arrays.asList("^/uaa/userinfo$", "^/uaa/logout\\.do$"));
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().setAllowedUris(allowedUris);

        List<String> allowedOrigins = new ArrayList<>(Collections.singletonList("example.com$"));
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().setAllowedOrigins(allowedOrigins);

        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().setAllowedHeaders(
                Arrays.asList("Accept", "Authorization", "X-Requested-With"));

        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().setMaxAge(187000);

        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().setAllowedCredentials(true);
    }

    private void setupBaselineCorsPolicyDefaultConfiguration() {
        List<String> allowedMethods = List.of(GET.toString(), POST.toString(),
                PUT.toString(), DELETE.toString());
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().setAllowedMethods(allowedMethods);
        List<String> allowedUris = new ArrayList<>(Arrays.asList("^/uaa/userinfo$", "^/uaa/logout\\.do$"));
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().setAllowedUris(allowedUris);
        List<String> allowedOrigins = new ArrayList<>(Collections.singletonList("example.com$"));
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().setAllowedOrigins(allowedOrigins);
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().setAllowedHeaders(
                Arrays.asList("Accept", "Authorization", "X-Requested-With"));
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().setMaxAge(187000);
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().setAllowedCredentials(true);
    }

    private static FilterChain newMockFilterChain() {
        return (request, response) -> {
            // Do nothing.
        };
    }
}
