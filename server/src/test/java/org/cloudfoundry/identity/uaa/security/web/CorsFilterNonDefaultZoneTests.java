package org.cloudfoundry.identity.uaa.security.web;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.OPTIONS;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.METHOD_NOT_ALLOWED;
import static org.springframework.http.HttpStatus.OK;

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
    void requestWithInvalidOrigins(String method, String url, String origin, String message) throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest(method, url);
        request.addHeader("Origin", origin);
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(FORBIDDEN.value());
        assertThat(response.getErrorMessage()).isEqualTo(message);
    }

    @Test
    void sameOriginRequest() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
    }

    // happy path
    @Test
    void requestExpectXhrCorsResponse() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("example.com");
    }

    @Test
    void requestWithAllowedOriginPatterns() throws ServletException, IOException {
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().getAllowedOriginPatterns()
                .add(Pattern.compile("bunnyoutlet-shop.com$"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "bunnyoutlet-shop.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
    }

    @Test
    void requestWithAllowedUriPatterns() throws ServletException, IOException {
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().getAllowedUriPatterns()
                .add(Pattern.compile("/uaa/*"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/login");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
    }

    @Test
    void requestWithMethodNotAllowed() throws ServletException, IOException {
        List<String> allowedMethods = List.of(GET.toString(), OPTIONS.toString(), DELETE.toString());
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().setAllowedMethods(allowedMethods);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(METHOD_NOT_ALLOWED.value());
        assertThat(response.getErrorMessage()).isEqualTo("Illegal method.");
    }

    // preflight happy path
    @Test
    void preFlightExpectXhrCorsResponse() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("example.com");
        assertThat(response.getHeaderValue("Access-Control-Allow-Methods")).isEqualTo("GET, POST, PUT, DELETE");
        assertThat(response.getHeaderValue("Access-Control-Allow-Headers")).isEqualTo("Authorization, X-Requested-With");
        assertThat(response.getHeaderValue("Access-Control-Max-Age")).isEqualTo("187000");
        assertThat(response.getStatus()).isEqualTo(OK.value());
    }

    @Test
    void preFlightWrongOriginSpecified() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "bunnyoutlet.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal origin");
    }

    @Test
    void preFlightRequestNoRequestMethod() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getErrorMessage()).isEqualTo("Access-Control-Request-Method header is missing");
        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("example.com");
    }

    @Test
    void preFlightRequestMethodNotAllowed() throws ServletException, IOException {
        List<String> allowedMethods = List.of(GET.toString(), PUT.toString(), DELETE.toString());
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().setAllowedMethods(allowedMethods);

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Access-Control-Request-Method", "POST");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(405);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal method requested");
    }

    @Test
    void preFlightRequestHeaderNotAllowed() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With, X-Not-Allowed");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal header requested");
    }

    @Test
    void preFlightRequestUriNotAllowed() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/login");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "X-Requested-With");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal request URI");
    }

    @Test
    void preFlightOriginNotAllowed() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "X-Requested-With");
        request.addHeader("Origin", "bunnyoutlet.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal origin");
    }

    // default cors
    @ParameterizedTest
    @CsvSource({
            "GET, /uaa/userinfo, <script>alert('1ee7 h@x0r')</script>, Invalid origin",
            "GET, /uaa/userinfo, bunnyoutlet.com, Illegal origin",
            "GET, /uaa/login, example.com, Illegal request URI",
    })
    void defaultCorsWithInvalidOrigins(String method, String url, String origin, String message) throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest(method, url);
        request.addHeader("Origin", origin);
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(FORBIDDEN.value());
        assertThat(response.getErrorMessage()).isEqualTo(message);
    }

    @Test
    void defaultCorsWithSameOrigin() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
    }

    // happy path
    @Test
    void defaultCorsExpectStandardCorsResponse() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("example.com");
    }

    @Test
    void defaultCorsWithAllowedOriginPatterns() throws ServletException, IOException {
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().getAllowedOriginPatterns()
                .add(Pattern.compile("bunnyoutlet.com$"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "bunnyoutlet.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
    }

    @Test
    void defaultCorsWithAllowedUriPatterns() throws ServletException, IOException {
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().getAllowedUriPatterns()
                .add(Pattern.compile("/uaa/*"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/login");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
    }

    @Test
    void defaultCorsWithMethodNotAllowed() throws ServletException, IOException {
        List<String> allowedMethods = List.of(GET.toString(), OPTIONS.toString(), DELETE.toString());
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().setAllowedMethods(allowedMethods);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(METHOD_NOT_ALLOWED.value());
        assertThat(response.getErrorMessage()).isEqualTo("Illegal method.");
    }

    // preflight happy path
    @Test
    void defaultCorsPreFlightExpectStandardCorsResponse() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("example.com");
        assertThat(response.getHeaderValue("Access-Control-Allow-Methods")).isEqualTo("GET, POST, PUT, DELETE");
        assertThat(new CorsFilter(mockIdentityZoneManager, false).
                splitCommaDelimitedString((String) response.getHeaderValue("Access-Control-Allow-Headers"))).containsExactlyInAnyOrder("Authorization");
        assertThat(response.getHeaderValue("Access-Control-Max-Age")).isEqualTo("187000");
    }

    @Test
    void defaultCorsPreFlightWrongOriginSpecified() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "bunnyoutlet.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal origin");
    }

    @Test
    void defaultCorsPreFlightRequestNoRequestMethod() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getErrorMessage()).isEqualTo("Access-Control-Request-Method header is missing");
        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("example.com");
    }

    @Test
    void defaultCorsPreFlightRequestMethodNotAllowed() throws ServletException, IOException {
        List<String> allowedMethods = List.of(GET.toString(), PUT.toString(), DELETE.toString());
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().setAllowedMethods(allowedMethods);

        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Access-Control-Request-Method", "POST");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(405);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal method requested");
    }

    @Test
    void defaultCorsPreFlightRequestHeaderNotAllowed() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Not-Allowed");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal header requested");
    }

    @Test
    void defaultCorsPreFlightRequestUriNotAllowed() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/login");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal request URI");
    }

    @Test
    void defaultCorsPreFlightOriginNotAllowed() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Origin", "bunnyoutlet.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal origin");
    }

    @Test
    void requestWithAllowedOriginPatternsEnforcingSystemZonePolicy() throws ServletException, IOException {
        CorsFilter corsFilter = new CorsFilter(mockIdentityZoneManager, true);
        corsFilter.setCorsXhrAllowedOrigins(List.of("example.com"));
        corsFilter.initialize();

        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().getAllowedOriginPatterns()
                .add(Pattern.compile("bunnyoutlet-shop.com$"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "bunnyoutlet-shop.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(FORBIDDEN.value());
        assertThat(response.getErrorMessage()).isEqualTo("Illegal origin");
    }

    @Test
    void defaultCorsPreFlightRequestMethodNotAllowedEnforcingSystemZonePolicy() throws ServletException, IOException {
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

        assertThat(response.getStatus()).isEqualTo(OK.value());
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
