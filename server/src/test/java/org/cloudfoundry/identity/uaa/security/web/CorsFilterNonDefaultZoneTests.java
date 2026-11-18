package org.cloudfoundry.identity.uaa.security.web;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import com.google.re2j.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
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
    void requestWithInvalidOrigins(String method, String url, String origin, String message) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, url);
        request.addHeader("Origin", origin);
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(FORBIDDEN.value());
        assertThat(response.getErrorMessage()).isEqualTo(message);
    }

    @Test
    void sameOriginRequest() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
    }

    // happy path
    @Test
    void requestExpectXhrCorsResponse() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("example.com");
    }

    @Test
    void requestWithAllowedOriginPatterns() throws Exception {
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().getAllowedOriginPatterns()
                .add(Pattern.compile("bunnyoutlet-shop.com$"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "bunnyoutlet-shop.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
    }

    @Test
    void requestWithAllowedUriPatterns() throws Exception {
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().getAllowedUriPatterns()
                .add(Pattern.compile("/uaa/*"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/login");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
    }

    @Test
    void requestWithMethodNotAllowed() throws Exception {
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
    void preFlightExpectXhrCorsResponse() throws Exception {
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
    void preFlightWrongOriginSpecified() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "bunnyoutlet.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal origin");
    }

    @Test
    void preFlightRequestNoRequestMethod() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getErrorMessage()).isEqualTo("Access-Control-Request-Method header is missing");
        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("example.com");
    }

    @Test
    void preFlightRequestMethodNotAllowed() throws Exception {
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
    void preFlightRequestHeaderNotAllowed() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Requested-With, X-Not-Allowed");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal header requested");
    }

    @Test
    void preFlightRequestUriNotAllowed() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/login");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "X-Requested-With");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal request URI");
    }

    @Test
    void preFlightOriginNotAllowed() throws Exception {
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
    void defaultCorsWithInvalidOrigins(String method, String url, String origin, String message) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, url);
        request.addHeader("Origin", origin);
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(FORBIDDEN.value());
        assertThat(response.getErrorMessage()).isEqualTo(message);
    }

    @Test
    void defaultCorsWithSameOrigin() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
    }

    // happy path
    @Test
    void defaultCorsExpectStandardCorsResponse() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("example.com");
    }

    @Test
    void defaultCorsWithAllowedOriginPatterns() throws Exception {
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().getAllowedOriginPatterns()
                .add(Pattern.compile("bunnyoutlet.com$"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "bunnyoutlet.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
    }

    @Test
    void defaultCorsWithAllowedUriPatterns() throws Exception {
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration().getAllowedUriPatterns()
                .add(Pattern.compile("/uaa/*"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/login");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(OK.value());
    }

    @Test
    void defaultCorsWithMethodNotAllowed() throws Exception {
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
    void defaultCorsPreFlightExpectStandardCorsResponse() throws Exception {
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
    void defaultCorsPreFlightWrongOriginSpecified() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "bunnyoutlet.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal origin");
    }

    @Test
    void defaultCorsPreFlightRequestNoRequestMethod() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getErrorMessage()).isEqualTo("Access-Control-Request-Method header is missing");
        assertThat(response.getHeaderValue("Access-Control-Allow-Origin")).isEqualTo("example.com");
    }

    @Test
    void defaultCorsPreFlightRequestMethodNotAllowed() throws Exception {
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
    void defaultCorsPreFlightRequestHeaderNotAllowed() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Headers", "Authorization, X-Not-Allowed");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal header requested");
    }

    @Test
    void defaultCorsPreFlightRequestUriNotAllowed() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/login");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Origin", "example.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal request URI");
    }

    @Test
    void defaultCorsPreFlightOriginNotAllowed() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/uaa/userinfo");
        request.addHeader("Access-Control-Request-Method", "GET");
        request.addHeader("Access-Control-Request-Headers", "Authorization");
        request.addHeader("Origin", "bunnyoutlet.com");
        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getErrorMessage()).isEqualTo("Illegal origin");
    }

    @Test
    void requestWithAllowedOriginPatternsEnforcingSystemZonePolicy() throws Exception {
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
    void defaultCorsPreFlightRequestMethodNotAllowedEnforcingSystemZonePolicy() throws Exception {
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

    @Test
    void pathologicalZoneOriginPatternRejectsWithinTimeLimit() throws Exception {
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration()
                .setAllowedOrigins(List.of("^(https?://)?(([a-z0-9]+)+\\.)+$"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "https://" + "a".repeat(28) + "!");

        org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(java.time.Duration.ofSeconds(1),
                () -> corsFilter.doFilter(request, response, filterChain));
        org.assertj.core.api.Assertions.assertThat(response.getStatus()).isEqualTo(FORBIDDEN.value());
    }

    @Test
    void pathologicalZoneOriginPatternRejectsWithoutOverflowingTheRequestThread() throws Exception {
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration()
                .setAllowedOrigins(List.of("^https://(a|aa)+$"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "https://" + "a".repeat(7000) + "!");

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(FORBIDDEN.value());
    }

    @Test
    void pathologicalZoneUriPatternRejectsWithoutOverflowingTheRequestThread() throws Exception {
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration()
                .setAllowedUris(List.of("^/(a|aa)+$"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/" + "a".repeat(7000) + "!");
        request.addHeader("Origin", "example.com");

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(FORBIDDEN.value());
    }

    @Test
    void patternsThatNeedBacktrackingAreNotUsed() throws Exception {
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration()
                .setAllowedOrigins(List.of("^https://(?=example)example\\.com$"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "https://example.com");

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(FORBIDDEN.value());
    }

    @Test
    void patternsWithCostlyCompilationAreNotUsed() throws Exception {
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration()
                .setAllowedUris(List.of("((((a{1000}){1000}){1000}){1000})"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");

        org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(java.time.Duration.ofSeconds(2),
                () -> corsFilter.doFilter(request, response, filterChain));
        assertThat(response.getStatus()).isEqualTo(FORBIDDEN.value());
    }

    @Test
    void tooManyPatternsAreNotUsed() throws Exception {
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration()
                .setAllowedOrigins(Collections.nCopies(33, ".*"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(FORBIDDEN.value());
    }

    @Test
    void originAtTheLengthLimitIsMatchedAndLongerOriginIsRejected() throws Exception {
        var configuration = identityZone.getConfig().getCorsPolicy().getDefaultConfiguration();
        configuration.setAllowedOrigins(List.of(".*"));
        configuration.setAllowedUris(List.of(".*"));

        assertThat(statusForOrigin("a".repeat(2048))).isEqualTo(OK.value());
        assertThat(statusForOrigin("a".repeat(2049))).isEqualTo(FORBIDDEN.value());
    }

    @Test
    void uriAtTheLengthLimitIsMatchedAndLongerUriIsRejected() throws Exception {
        var configuration = identityZone.getConfig().getCorsPolicy().getDefaultConfiguration();
        configuration.setAllowedOrigins(List.of(".*"));
        configuration.setAllowedUris(List.of(".*"));

        assertThat(statusForUri("/" + "a".repeat(8191))).isEqualTo(OK.value());
        assertThat(statusForUri("/" + "a".repeat(8192))).isEqualTo(FORBIDDEN.value());
    }

    @Test
    void originPatternIsMatchedAgainstTheWholeOrigin() throws Exception {
        // example.com$ has no ^, so it is used as written: matches() must not accept a longer host that ends the same way.
        assertThat(statusForOrigin("evil-example.com")).isEqualTo(FORBIDDEN.value());
    }

    @Test
    void caseInsensitiveOriginPatternMatches() throws Exception {
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration()
                .setAllowedOrigins(List.of("(?i)^https://example\\.com$"));

        assertThat(statusForOrigin("https://EXAMPLE.com")).isEqualTo(OK.value());
    }

    @Test
    void listOfExactlyThePermittedNumberOfPatternsIsUsed() throws Exception {
        identityZone.getConfig().getCorsPolicy().getDefaultConfiguration()
                .setAllowedOrigins(Collections.nCopies(32, "example\\.com"));

        assertThat(statusForOrigin("example.com")).isEqualTo(OK.value());
    }

    @Test
    void tooManyPatternsAreNotUsedForXhrRequests() throws Exception {
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration()
                .setAllowedOrigins(Collections.nCopies(33, ".*"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(FORBIDDEN.value());
    }

    @Test
    void patternsThatNeedBacktrackingAreNotUsedForXhrRequests() throws Exception {
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration()
                .setAllowedUris(List.of("^/uaa/(?=user)userinfo$"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", "example.com");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        corsFilter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(FORBIDDEN.value());
    }

    @Test
    void repeatedXhrRequestsDoNotAccumulateCompiledPatternsInTheZone() throws Exception {
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
            request.addHeader("Origin", "example.com");
            request.addHeader("X-Requested-With", "XMLHttpRequest");
            MockHttpServletResponse result = new MockHttpServletResponse();
            corsFilter.doFilter(request, result, filterChain);
            assertThat(result.getStatus()).isEqualTo(OK.value());
        }
        var configuration = identityZone.getConfig().getCorsPolicy().getXhrConfiguration();
        assertThat(configuration.getAllowedOriginPatterns()).isEmpty();
        assertThat(configuration.getAllowedUriPatterns()).isEmpty();
    }

    private int statusForOrigin(String origin) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
        request.addHeader("Origin", origin);
        MockHttpServletResponse result = new MockHttpServletResponse();
        corsFilter.doFilter(request, result, filterChain);
        return result.getStatus();
    }

    private int statusForUri(String uri) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
        request.addHeader("Origin", "example.com");
        MockHttpServletResponse result = new MockHttpServletResponse();
        corsFilter.doFilter(request, result, filterChain);
        return result.getStatus();
    }

    @Test
    void repeatedRequestsDoNotAccumulateCompiledPatternsInTheZone() throws Exception {
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
            request.addHeader("Origin", "example.com");
            MockHttpServletResponse result = new MockHttpServletResponse();
            corsFilter.doFilter(request, result, filterChain);
            assertThat(result.getStatus()).isEqualTo(OK.value());
        }
        var configuration = identityZone.getConfig().getCorsPolicy().getDefaultConfiguration();
        assertThat(configuration.getAllowedOriginPatterns()).isEmpty();
        assertThat(configuration.getAllowedUriPatterns()).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"origin", "uri"})
    void zeroWidthRepetitionRejectsWithinDeadline(String target, @TempDir Path directory) throws Exception {
        String classpath = System.getProperty("uaa.test.classpath");
        assertThat(classpath).as("isolated probe runtime classpath").isNotBlank();
        Path output = directory.resolve("cors-probe.log");
        Process probe = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Xmx128m", "-cp", classpath, ZeroWidthCorsProbe.class.getName(), target)
                .redirectErrorStream(true).redirectOutput(output.toFile()).start();
        boolean completed;
        try {
            // JVM and Mockito startup have a separate deadline from CORS evaluation.
            await().atMost(Duration.ofSeconds(30)).until(() ->
                    !probe.isAlive() || Files.readString(output).contains("CORS_PROBE_READY"));
            assertThat(Files.readString(output)).as("probe finished startup").contains("CORS_PROBE_READY");
            probe.getOutputStream().write(1);
            probe.getOutputStream().flush();
            completed = probe.waitFor(8, TimeUnit.SECONDS);
        } finally {
            if (probe.isAlive()) {
                probe.destroyForcibly();
                assertThat(probe.waitFor(5, TimeUnit.SECONDS)).as("probe process terminated").isTrue();
            }
        }
        String log = Files.readString(output);
        assertThat(completed).as("%s CORS evaluation must terminate within 8 seconds: %s", target, log).isTrue();
        assertThat(probe.exitValue()).as("costly %s pattern must reject the request: %s", target, log).isZero();
    }

    /** The parent can forcibly terminate this JVM even if Java regex ignores thread interruption. */
    public static class ZeroWidthCorsProbe {
        public static void main(String[] args) throws Exception {
            CorsFilterNonDefaultZoneTests fixture = new CorsFilterNonDefaultZoneTests();
            fixture.setUp();
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaa/userinfo");
            request.addHeader("Origin", "example.com");
            fixture.corsFilter.doFilter(request, fixture.response, fixture.filterChain);
            if (fixture.response.getStatus() != OK.value()) {
                throw new AssertionError("Baseline request must be allowed");
            }
            fixture.response = new MockHttpServletResponse();
            // OncePerRequestFilter skips a request it has already filtered, so the costly call needs a new one.
            request = new MockHttpServletRequest("GET", "/uaa/userinfo");
            request.addHeader("Origin", "example.com");
            var config = fixture.identityZone.getConfig().getCorsPolicy().getDefaultConfiguration();
            // Java regex would spin on this for minutes; RE2/J rejects the lookahead, so the request fails closed.
            String pattern = "^(?:(?=){2147483647}){2147483647}.*$";
            if ("origin".equals(args[0])) {
                config.setAllowedOrigins(List.of(pattern));
            } else {
                config.setAllowedUris(List.of(pattern));
            }
            System.out.println("CORS_PROBE_READY");
            System.out.flush();
            if (System.in.read() != 1) {
                throw new AssertionError("Parent did not start CORS evaluation");
            }
            fixture.corsFilter.doFilter(request, fixture.response, fixture.filterChain);
            if (fixture.response.getStatus() != FORBIDDEN.value()) {
                throw new AssertionError("Costly pattern must reject the request: " + fixture.response.getStatus());
            }
        }
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
        return (_, _) -> {
            // Do nothing.
        };
    }
}
