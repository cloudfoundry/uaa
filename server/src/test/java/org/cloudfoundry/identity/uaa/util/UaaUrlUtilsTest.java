package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.InvalidUrlException;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

@ExtendWith(PollutionPreventionExtension.class)
class UaaUrlUtilsTest {

    private final List<String> invalidWildCardUrls = Arrays.asList(
            "*",
            "**",
            "*/**",
            "**/*",
            "*/*",
            "**/**");
    private final List<String> invalidHttpWildCardUrls = Arrays.asList(
            "http://*",
            "http://**",
            "http://*/**",
            "http://*/*",
            "http://**/*",
            "http://a*",
            "http://*.com",
            "http://*domain*",
            "http://domain.*",
            "http://*domain.com",
            "http://{sub}.example.com/",
            "http://*domain/path",
            "http://local*",
            "*.valid.com/*/with/path**",
            "http://**/path",
            "https://*.*.*.com/*/with/path**",
            "www.*/path",
            "www.invalid.com/*/with/path**",
            "www.*.invalid.com/*/with/path**",
            "http://username:password@*.com",
            "http://username:password@*.com/path",
            "org-;cl0udfoundry-identity://mobile-android-app.com/view"
    );
    private final List<String> validUrls = Arrays.asList(
            "http://localhost",
            "http://localhost:8080",
            "http://localhost:8080/uaa",
            "http://valid.com",
            "http://sub.valid.com",
            "http://valid.com/with/path",
            "https://subsub.sub.valid.com/**",
            "https://valid.com/path/*/path",
            "http://sub.valid.com/*/with/path**",
            "http*://sub.valid.com/*/with/path**",
            "http*://*.valid.com/*/with/path**",
            "http://*.valid.com/*/with/path**",
            "https://*.valid.com/*/with/path**",
            "https://*.*.valid.com/*/with/path**",
            "http://sub*.valid.com/*/with/path**",
            "http://*.domain.com",
            "http://**.domain.com",
            "http://example.com/{path-var}",
            "http://username:password@some.server.com",
            "http://*:*@some.server.com",
            "http://username:password@some.server.com/path",
            "http://under_score_subdomain.example.com",
            "http://under_score_subdomain.ex_ample.com",
            "http://dash-subdomain.example.com",
            "http://dash-subdomain.ex-ample.com",
            "cool-app://example.com",
            "org.cloudfoundry.identity://mobile-windows-app.com/view",
            "org+cloudfoundry+identity://mobile-ios-app.com/view",
            "org-cl0udfoundry-identity://mobile-android-app.com/view"
    );

    private final List<String> validSubdomains = Arrays.asList(
            "test1",
            "test-test2",
            "t"
    );

    private final List<String> invalidSubdomains = Arrays.asList(
            "",
            "-t",
            "t-",
            "test_test2"
    );

    @BeforeEach
    void setUp() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.setRequestAttributes(null);
    }

    @Test
    void getParameterMapFromQueryString() {
        String url = "http://localhost:8080/uaa/oauth/authorize?client_id=app-addnew-false4cEsLB&response_type=code&redirect_uri=http%3A%2F%2Fnosuchhostname%3A0%2Fnosuchendpoint";
        Map<String, String[]> map = UaaUrlUtils.getParameterMap(url);
        assertThat(map).isNotNull();
        assertThat(map.get("client_id")[0]).isEqualTo("app-addnew-false4cEsLB");
        assertThat(map.get("redirect_uri")[0]).isEqualTo("http://nosuchhostname:0/nosuchendpoint");
    }

    @Test
    void getParameterMapFromInvalidQueryString() {
        String url = "http://localhost:8080/uaa/oauth/authorize?client_id&response_type=code&redirect_uri=&=value";
        Map<String, String[]> map = UaaUrlUtils.getParameterMap(url);
        assertThat(map).isNotNull();
        assertThat(map.get("response_type")[0]).isEqualTo("code");
        assertThat(map.get("redirect_uri")[0]).isEmpty();
        assertThat(map.get("client_id")).containsExactly(new String[0]);
    }

    @Test
    void getUaaUrl() {
        assertThat(UaaUrlUtils.getUaaUrl(UaaStringUtils.EMPTY_STRING, IdentityZone.getUaa())).isEqualTo("http://localhost");
    }

    @Test
    void getBaseURL() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("login.domain");
        request.setRequestURI("/something");
        request.setServletPath("/something");
        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);

        assertThat(UaaUrlUtils.getBaseURL(request)).isEqualTo("http://login.domain");
    }

    @Test
    void getBaseURLWhenPathMatchesHostname() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("login.domain");
        request.setRequestURI("/login");
        request.setServletPath("/login");
        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);

        assertThat(UaaUrlUtils.getBaseURL(request)).isEqualTo("http://login.domain");
    }

    @Test
    void getBaseURLOnLocalhost() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setRequestURI("/uaa/something");
        request.setServletPath("/something");
        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);

        assertThat(UaaUrlUtils.getBaseURL(request)).isEqualTo("http://localhost:8080/uaa");
    }

    @Test
    void zoneAwareUaaUrl() {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "subdomain");
        assertThat(UaaUrlUtils.getUaaUrl("", zone)).isEqualTo("http://localhost");
        assertThat(UaaUrlUtils.getUaaUrl(UaaStringUtils.EMPTY_STRING, true, zone)).isEqualTo("http://subdomain.localhost");
    }

    @Test
    void zoneAwareUaaUrlFromUriComponentsBuilder() {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString("http://external.domain.org").path("/custom-path");
        IdentityZone zone = MultitenancyFixture.identityZone("id", "subdomain");
        assertThat(UaaUrlUtils.getUaaUrl(builder, true, zone)).isEqualTo("http://subdomain.external.domain.org/custom-path");
    }

    @Test
    void getUaaUrlWithPath() {
        assertThat(UaaUrlUtils.getUaaUrl("/login", IdentityZone.getUaa())).isEqualTo("http://localhost/login");
    }

    @Test
    void getUaaUrlWithZone() {
        IdentityZone zone = MultitenancyFixture.identityZone("zone1", "zone1");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("zone1.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        assertThat(UaaUrlUtils.getUaaUrl(UaaStringUtils.EMPTY_STRING, zone)).isEqualTo("http://zone1.localhost");
    }

    @Test
    void getUaaUrlWithZoneAndPath() {
        IdentityZone zone = MultitenancyFixture.identityZone("zone1", "zone1");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("zone1.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        assertThat(UaaUrlUtils.getUaaUrl("/login", zone)).isEqualTo("http://zone1.localhost/login");
    }

    @Test
    void getHost() {
        assertThat(UaaUrlUtils.getUaaHost(IdentityZone.getUaa())).isEqualTo("localhost");
    }

    @Test
    void getHostWithZone() {
        MultitenancyFixture.identityZone("zone1", "zone1");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("zone1.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);

        assertThat(UaaUrlUtils.getUaaHost(IdentityZone.getUaa())).isEqualTo("zone1.localhost");
    }

    @Test
    void localhostPortAndContextPathUrl() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setContextPath("/uaa");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        String url = UaaUrlUtils.getUaaUrl("/something", IdentityZone.getUaa());
        assertThat(url).isEqualTo("http://localhost:8080/uaa/something");
    }

    @Test
    void securityProtocol() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerPort(8443);
        request.setServerName("localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        String url = UaaUrlUtils.getUaaUrl("/something", IdentityZone.getUaa());
        assertThat(url).isEqualTo("https://localhost:8443/something");
    }

    @Test
    void multiDomainUrls() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("login.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        String url = UaaUrlUtils.getUaaUrl("/something", IdentityZone.getUaa());
        assertThat(url).isEqualTo("http://login.localhost/something");
    }

    @Test
    void zonedAndMultiDomainUrls() {
        IdentityZone zone = MultitenancyFixture.identityZone("testzone1-id", "testzone1");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("testzone1.login.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        String url = UaaUrlUtils.getUaaUrl("/something", zone);
        assertThat(url).isEqualTo("http://testzone1.login.localhost/something");
    }

    @Test
    void xForwardedPrefixHeaderIsIgnored() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("login.localhost");
        request.addHeader("X-Forwarded-Prefix", "/prefix");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        String url = UaaUrlUtils.getUaaUrl("/something", IdentityZone.getUaa());
        assertThat(url).isEqualTo("http://login.localhost/something");
    }

    @Test
    void findMatchingRedirectUri_usesAntPathMatching() {
        //matches pattern
        String matchingRedirectUri1 = UaaUrlUtils.findMatchingRedirectUri(Collections.singleton("http://matching.redirect/*"), "http://matching.redirect/", null);
        assertThat(matchingRedirectUri1).isEqualTo("http://matching.redirect/");

        //matches pattern

        String matchingRedirectUri2 = UaaUrlUtils.findMatchingRedirectUri(Collections.singleton("http://matching.redirect/*"), "http://matching.redirect/anything-but-forward-slash", null);
        assertThat(matchingRedirectUri2).isEqualTo("http://matching.redirect/anything-but-forward-slash");

        //does not match pattern, but no fallback
        matchingRedirectUri2 = UaaUrlUtils.findMatchingRedirectUri(Collections.singleton("http://matching.redirect/*"), "http://does.not.match/redirect", null);
        assertThat(matchingRedirectUri2).isEqualTo("http://does.not.match/redirect");

        //does not match pattern, but fallback provided
        matchingRedirectUri2 = UaaUrlUtils.findMatchingRedirectUri(Collections.singleton("http://matching.redirect/*"), "http://does.not.match/redirect", "http://fallback.url/redirect");
        assertThat(matchingRedirectUri2).isEqualTo("http://fallback.url/redirect");

        String pattern2 = "http://matching.redirect/**";
        String redirect3 = "http://matching.redirect/whatever/you/want";
        String matchingRedirectUri3 = UaaUrlUtils.findMatchingRedirectUri(Collections.singleton(pattern2), redirect3, null);
        assertThat(matchingRedirectUri3).isEqualTo(redirect3);

        String pattern3 = "http://matching.redirect/?";
        String redirect4 = "http://matching.redirect/t";
        String matchingRedirectUri4 = UaaUrlUtils.findMatchingRedirectUri(Collections.singleton(pattern3), redirect4, null);
        assertThat(matchingRedirectUri4).isEqualTo(redirect4);

        String redirect5 = "http://non-matching.redirect/two";
        String fallback = "http://fallback.to/this";
        String matchingRedirectUri5 = UaaUrlUtils.findMatchingRedirectUri(Collections.singleton(pattern3), redirect5, fallback);
        assertThat(matchingRedirectUri5).isEqualTo(fallback);
    }

    @ParameterizedTest
    @CsvSource({
            "http://example.com/*, http://example.com/?param=value",
            "http://example.com/*, http://example.com/page#1",
            "http://example.com/**/mypage*, http://example.com/a/b/mypage?a=b",
            "http://abc?.example.com, http://abcd.example.com",
            "http://www.*.example.com, http://www.tv.example.com",
            "a/**, a/b/c",
            "a/b/*, a/b/c",
            "ab?/*, abc/def",
            "/abc/*, /abc/ab",
            "/abc/*, /abc/ab@c",
            "http://foo.bar.com:8080, http://foo.bar.com:8080",
            "http://foo.bar.com:8080/**, http://foo.bar.com:8080/app/foo",
            "http://*.bar.com:8080/**, http://foo.bar.com:8080/app/foo",
            "http://*.bar.com*, http://foo.bar.com:80",
            "https://*.bar.com*, https://foo.bar.com:443",
            "myapp://callback, myapp://callback",
            "myapp://callback*, myapp://callback#token=xyz123",
            "https://*.example.com:*, https://john.doe@www.example.com:123",
            "http://*.example.com, http://AAA@foo.example.com",
            "http://*.some.server.com, http://username:password@foo.some.server.com",
            "http://*some.server.com, http://username:password@some.server.com",
    })
    void findMatchingRedirectUri_urlParametersShouldResolveInIncomingUrl(
            String allowedRedirectUrl,
            String incomingRedirectUrl) {
        final String fallbackRedirectUrl = "http://fallback.to/this";
        Set<String> allowedRedirectUrlGlobPatterns = Collections.singleton(allowedRedirectUrl);

        assertThat(UaaUrlUtils.findMatchingRedirectUri(
                allowedRedirectUrlGlobPatterns,
                incomingRedirectUrl,
                fallbackRedirectUrl
        )).isEqualTo(incomingRedirectUrl);
    }

    @ParameterizedTest
    @CsvSource({
            "http://*.example.com, http://attacker.com?.example.com",
            "http://*.example.com, http://attacker.com\\.example.com",
            "http://*.example.com, http://attacker.com/.example.com",
            "http://*.example.com, http://attacker.com#.example.com",
            "http://example.com, http://tv.example.com",
            "http://www.*.example.com, http://www.attacker.com?.example.com",
            "a/**/c, a/b/c/d",
            "a/b/*, a/b/c/d",
            "ab?/*, abcd/ef",
            "a/*, ",
            "/abc/*, a/abc/ab",
            "http://*.bar.com:8080, http://attacker.com?.bar.com:8080",
            "http://*.bar.com:8080/**, http://attacker.com#foo.bar.com:8080/app/foo",
            "https://*.bar.com:8080/**, https://attacker.com#foo.bar.com:8443/app/foo",
            "myapp://callback, myapp://badcallback",
            "myapp://callback*, myapp://badcallback#token=123xyz",
            "http://*.example.com, http://AAA@attacker.com?.example.com",
            "http://*.example.com, http://AAA@@attacker.com?.example.com",
            "http://*.example.com, http://AAA@@@attacker.com?.example.com",
            "http://*.example.com, http://AAA@@@@attacker.com?.example.com",
            "http://*.example.com, http://AAA@attacker.com#.example.com",
            "http://*.example.com, http://AAA@@attacker.com#.example.com",
            "http://*some.server.com, http://username:password@attacker.com#some.server.com",
            "http://*.server.com, http://username:password@attacker.com?some.server.com",
            "http://*.some.server.com, http://username:password@attacker.com?.some.server.com",
    })
    void findMatchingRedirectUri_badRedirectUrlShouldResolveInFallbackUrl(
            String allowedRedirectUrl,
            String incomingMaliciousRedirectUrl) {
        final String fallbackRedirectUrl = "http://fallback.to/this";
        Set<String> allowedRedirectUrlGlobPatterns = Collections.singleton(allowedRedirectUrl);

        assertThat(UaaUrlUtils.findMatchingRedirectUri(
                allowedRedirectUrlGlobPatterns,
                incomingMaliciousRedirectUrl,
                fallbackRedirectUrl
        )).isEqualTo(fallbackRedirectUrl);
    }

    @Test
    void addQueryParameter() {
        String url = "http://sub.domain.com";
        String name = "name";
        String value = "value";
        assertThat(UaaUrlUtils.addQueryParameter(url, name, value)).isEqualTo("http://sub.domain.com?name=value");
        assertThat(UaaUrlUtils.addQueryParameter(url + "/", name, value)).isEqualTo("http://sub.domain.com/?name=value");
        assertThat(UaaUrlUtils.addQueryParameter(url + "?key=value", name, value)).isEqualTo("http://sub.domain.com?key=value&name=value");
        assertThat(UaaUrlUtils.addQueryParameter(url + "?key=value#frag=fragvalue", name, value)).isEqualTo("http://sub.domain.com?key=value&name=value#frag=fragvalue");
        assertThat(UaaUrlUtils.addQueryParameter(url + "#frag=fragvalue", name, value)).isEqualTo("http://sub.domain.com?name=value#frag=fragvalue");
    }

    @Test
    void addFragmentComponent() {
        String url = "http://sub.domain.com";
        String component = "name=value";
        assertThat(UaaUrlUtils.addFragmentComponent(url, component)).isEqualTo("http://sub.domain.com#name=value");
    }

    @Test
    void addFragmentComponentToPriorFragment() {
        String url = "http://sub.domain.com#frag";
        String component = "name=value";
        assertThat(UaaUrlUtils.addFragmentComponent(url, component)).isEqualTo("http://sub.domain.com#frag&name=value");
    }

    @Test
    void validateValidRedirectUri() {
        validateRedirectUri(validUrls, true);
        validateRedirectUri(convertToHttps(validUrls), true);
    }

    @Test
    void validateInvalidRedirectUri() {
        validateRedirectUri(invalidWildCardUrls, false);
        validateRedirectUri(invalidHttpWildCardUrls, false);
        validateRedirectUri(convertToHttps(invalidHttpWildCardUrls), false);
    }

    @Test
    void addSubdomainToUrl_givenUaaUrl() {
        String url = UaaUrlUtils.addSubdomainToUrl("http://localhost:8080", "somezone");
        assertThat(url).isEqualTo("http://somezone.localhost:8080");
    }

    @Test
    void addSubdomainToUrl_handlesEmptySubdomain() {
        String url = UaaUrlUtils.addSubdomainToUrl("http://localhost:8080", UaaStringUtils.EMPTY_STRING);
        assertThat(url).isEqualTo("http://localhost:8080");
    }

    @Test
    void addSubdomainToUrl_handlesEmptySubdomain_defaultZone() {
        String url = UaaUrlUtils.addSubdomainToUrl("http://localhost:8080", UaaStringUtils.EMPTY_STRING);
        assertThat(url).isEqualTo("http://localhost:8080");
    }

    @Test
    void addSudomain_handlesExtraSpaceInSubdomain() {
        String url = UaaUrlUtils.addSubdomainToUrl("http://localhost:8080", " somezone  ");
        assertThat(url).isEqualTo("http://somezone.localhost:8080");
    }

    @Test
    void addSudomain_handlesExtraSpaceInSubdomain_currentZone() {
        String url2 = UaaUrlUtils.addSubdomainToUrl("http://localhost:8080", " somezone2 ");
        assertThat(url2).isEqualTo("http://somezone2.localhost:8080");
    }

    @Test
    void addSubdomain_handlesUnexpectedDotInSubdomain() {
        String url = UaaUrlUtils.addSubdomainToUrl("http://localhost:8080", " somezone. ");
        assertThat(url).isEqualTo("http://somezone.localhost:8080");
    }

    @Test
    void addSubdomain_handlesUnexpectedDotInSubdomain_currentZone() {
        String url2 = UaaUrlUtils.addSubdomainToUrl("http://localhost:8080", " somezone2. ");
        assertThat(url2).isEqualTo("http://somezone2.localhost:8080");
    }

    @Test
    void uriHasMatchingHost() {
        assertThat(UaaUrlUtils.uriHasMatchingHost("http://test.com/test", "test.com")).isTrue();
        assertThat(UaaUrlUtils.uriHasMatchingHost("http://subdomain.test.com/test", "subdomain.test.com")).isTrue();
        assertThat(UaaUrlUtils.uriHasMatchingHost("http://1.2.3.4/test", "1.2.3.4")).isTrue();

        assertThat(UaaUrlUtils.uriHasMatchingHost(null, "test.com")).isFalse();
        assertThat(UaaUrlUtils.uriHasMatchingHost("http://not-test.com/test", "test.com")).isFalse();
        assertThat(UaaUrlUtils.uriHasMatchingHost("not-valid-url", "test.com")).isFalse();
        assertThat(UaaUrlUtils.uriHasMatchingHost("http://1.2.3.4/test", "test.com")).isFalse();
        assertThat(UaaUrlUtils.uriHasMatchingHost("http://test.com/test", "1.2.3.4")).isFalse();
        assertThat(UaaUrlUtils.uriHasMatchingHost("http://not.test.com/test", "test.com")).isFalse();
    }

    @Test
    void getHostForURI() {
        assertThat(UaaUrlUtils.getHostForURI("http://google.com")).isEqualTo("google.com");
        assertThat(UaaUrlUtils.getHostForURI("http://subdomain.uaa.com/nowhere")).isEqualTo("subdomain.uaa.com");
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> UaaUrlUtils.getHostForURI(UaaStringUtils.EMPTY_STRING));
    }

    @Test
    void getSubdomain() {
        assertThat(UaaUrlUtils.getSubdomain(null)).isNull();
        assertThat(UaaUrlUtils.getSubdomain(UaaStringUtils.EMPTY_STRING)).isEmpty();
        assertThat(UaaUrlUtils.getSubdomain("     ")).isEqualTo("     ");
        assertThat(UaaUrlUtils.getSubdomain("a")).isEqualTo("a.");
        assertThat(UaaUrlUtils.getSubdomain("    z     ")).isEqualTo("z.");
        assertThat(UaaUrlUtils.getSubdomain("a.b.c.d.e")).isEqualTo("a.b.c.d.e.");
    }

    @Test
    void validateValidSubdomains() {
        validSubdomains.forEach(testString -> assertThat(UaaUrlUtils.isValidSubdomain(testString)).isTrue());
    }

    @Test
    void validateInvalidSubdomains() {
        invalidSubdomains.forEach(testString -> assertThat(UaaUrlUtils.isValidSubdomain(testString)).isFalse());
    }

    @ParameterizedTest(name = "\"{0}\" should be normalized to \"/test1\"")
    @ValueSource(strings = {
            "/test1/.",
            "/test1/%2e",
            "/test1/%2E",
            "/test1/%252e",
            "/test1/%252E",
            "/test2/../test1",
            "/test2/%2e./test1",
            "/test2/%2E./test1",
            "/test2/%252e./test1",
            "/test2/%2525252E./test1",
            "/test2/%2525252e./test1",
            "/test2/%2525252E./test1",
            "/test2/%2525252e.%2ftest1",
            "/test2/%2525252e.%2Ftest1",
            "/test2/%2525252e.%2f%2e%2ftest1",
            "/test2/%2525252e.%2F%252e%2ftest1",
    })
    void validateUriPathDecoding(String uriPath) {
        assertThat(UaaUrlUtils.normalizeUri("https://example.com" + uriPath)).isEqualTo("https://example.com/test1");
    }

    @Test
    void validateUriPathDecodingDoesNotAffectQueryParams() {
        final String uriWithEncodedQueryParams = "https://example.com/test1?q1=%2e&q2=%2e%2e";
        assertThat(UaaUrlUtils.normalizeUri(uriWithEncodedQueryParams)).isEqualTo(uriWithEncodedQueryParams);
    }

    @Test
    void validateUriPathDecodingDoesNotAffectFragments() {
        final String uriWithEncodedQueryParams = "https://example.com/test1#%2e%2e";
        assertThat(UaaUrlUtils.normalizeUri(uriWithEncodedQueryParams)).isEqualTo(uriWithEncodedQueryParams);
    }

    @Test
    void validateUriPathDecodingLimit() {
        // URI path encoded more than MAX_URI_DECODES times
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> UaaUrlUtils.normalizeUri("https://example.com/test1/%25252525252e"));
    }

    @Test
    void validateNormalizeUriIfNull() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> UaaUrlUtils.normalizeUri("nohost"));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> UaaUrlUtils.normalizeUri(" ://host/path"));
    }

    @Test
    void validateMatchHostExceptionEndsInFalse() {
        assertThat(UaaUrlUtils.matchHost(" ", " ", null)).isFalse();
    }

    @Test
    void testisUrl() {
        assertThat(UaaUrlUtils.isUrl(UaaStringUtils.EMPTY_STRING)).isFalse();
        assertThat(UaaUrlUtils.isUrl(" ")).isFalse();
        assertThat(UaaUrlUtils.isUrl("http://localhost")).isTrue();
    }

    @Test
    void extractPathVariableFromUrl() {
        assertThat(UaaUrlUtils.extractPathVariableFromUrl(1, "/Users/id")).isEqualTo("id");
        assertThat(UaaUrlUtils.extractPathVariableFromUrl(3, "/Users/id")).isNull();
    }

    @Test
    void getRequestPath() {
        assertThat(UaaUrlUtils.getRequestPath(mock(HttpServletRequest.class))).isEmpty();
    }

    @ParameterizedTest
    @CsvSource({
            "/servlet, /pathInfo, /servlet/pathInfo",
            "/servlet, , /servlet",
            ",         /pathInfo, /pathInfo",
            ",         ,          ''"

    })
    void getRequestPathCombinesServletPathAndPathInfo(
            String servletPath, String pathInfo, String expected
    ) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath(servletPath);
        request.setPathInfo(pathInfo);

        assertThat(UaaUrlUtils.getRequestPath(request)).isEqualTo(expected);
    }

    @Test
    void legacyUriWithPortWildCard() {
        assertThat(UaaUrlUtils.isValidRegisteredRedirectUrl("http://localhost:*/callback")).isTrue();

        assertThat(UaaUrlUtils.isValidRegisteredRedirectUrl(UaaStringUtils.EMPTY_STRING)).isFalse();
        assertThat(UaaUrlUtils.isValidRegisteredRedirectUrl("http://localhost:80*/callback")).isFalse();
        assertThat(UaaUrlUtils.isValidRegisteredRedirectUrl("http://localhost:*8/callback")).isFalse();
    }

    @Test
    void invalidUrlExceptionIsThrown() {
        assertThatExceptionOfType(InvalidUrlException.class).isThrownBy(
                () -> UaaUrlUtils.fromUriString("invalid-url")
        );
    }

    private static void validateRedirectUri(List<String> urls, boolean result) {
        Map<String, String> failed = getUnsuccessfulUrls(urls, result);
        if (!failed.isEmpty()) {
            StringBuilder builder = new StringBuilder("\n");
            failed.forEach((key, value) -> builder.append(value).append("\n"));
            fail(builder.toString());
        }
    }

    enum CASE {
        AS_IS,
        UPPER_CASE,
        LOWER_CASE
    }

    private static Map<String, String> getUnsuccessfulUrls(List<String> urls, boolean result) {
        Map<String, String> failed = new LinkedHashMap<>();
        urls.forEach(
                url -> {
                    for (CASE c : CASE.values()) {
                        switch (c) {
                            case AS_IS:
                                break;
                            case LOWER_CASE:
                                url = url.toLowerCase();
                                break;
                            case UPPER_CASE:
                                url = url.toUpperCase();
                                break;
                        }
                        String message = "Assertion failed for " + (result ? "" : "in") + "valid url:" + url;
                        if (result != UaaUrlUtils.isValidRegisteredRedirectUrl(url)) {
                            failed.put(url, message);
                        }
                    }
                }
        );
        return failed;
    }

    private static List<String> convertToHttps(List<String> urls) {
        return urls.stream().map(url -> url.replace("http:", "https:")).toList();
    }
}
