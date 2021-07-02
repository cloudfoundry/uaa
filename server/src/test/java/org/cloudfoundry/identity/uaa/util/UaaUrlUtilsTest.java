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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.*;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(PollutionPreventionExtension.class)
class UaaUrlUtilsTest {

    private List<String> invalidWildCardUrls = Arrays.asList(
            "*",
            "**",
            "*/**",
            "**/*",
            "*/*",
            "**/**");
    private List<String> invalidHttpWildCardUrls = Arrays.asList(
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
    private List<String> validUrls = Arrays.asList(
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

    private List<String> validSubdomains = Arrays.asList(
            "test1",
            "test-test2",
            "t"
    );

    private List<String> invalidSubdomains = Arrays.asList(
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
        assertNotNull(map);
        assertEquals("app-addnew-false4cEsLB", map.get("client_id")[0]);
        assertEquals("http://nosuchhostname:0/nosuchendpoint", map.get("redirect_uri")[0]);
    }

    @Test
    void getUaaUrl() {
        assertEquals("http://localhost", UaaUrlUtils.getUaaUrl("", IdentityZone.getUaa()));
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

        assertEquals("http://login.domain", UaaUrlUtils.getBaseURL(request));
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

        assertEquals("http://login.domain", UaaUrlUtils.getBaseURL(request));
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

        assertEquals("http://localhost:8080/uaa", UaaUrlUtils.getBaseURL(request));
    }

    @Test
    void zoneAwareUaaUrl() {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "subdomain");
        assertEquals("http://localhost", UaaUrlUtils.getUaaUrl("", zone));
        assertEquals("http://subdomain.localhost", UaaUrlUtils.getUaaUrl("", true, zone));
    }

    @Test
    void getUaaUrlWithPath() {
        assertEquals("http://localhost/login", UaaUrlUtils.getUaaUrl("/login", IdentityZone.getUaa()));
    }

    @Test
    void getUaaUrlWithZone() {
        IdentityZone zone = MultitenancyFixture.identityZone("zone1", "zone1");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("zone1.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        assertEquals("http://zone1.localhost", UaaUrlUtils.getUaaUrl("", zone));
    }

    @Test
    void getUaaUrlWithZoneAndPath() {
        IdentityZone zone = MultitenancyFixture.identityZone("zone1", "zone1");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("zone1.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        assertEquals("http://zone1.localhost/login", UaaUrlUtils.getUaaUrl("/login", zone));
    }

    @Test
    void getHost() {
        assertEquals("localhost", UaaUrlUtils.getUaaHost(IdentityZone.getUaa()));
    }

    @Test
    void getHostWithZone() {
        IdentityZone zone = MultitenancyFixture.identityZone("zone1", "zone1");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("zone1.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);

        assertEquals("zone1.localhost", UaaUrlUtils.getUaaHost(IdentityZone.getUaa()));
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
        assertThat(url, is("http://localhost:8080/uaa/something"));
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
        assertThat(url, is("https://localhost:8443/something"));
    }

    @Test
    void multiDomainUrls() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("login.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        String url = UaaUrlUtils.getUaaUrl("/something", IdentityZone.getUaa());
        assertThat(url, is("http://login.localhost/something"));
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
        assertThat(url, is("http://testzone1.login.localhost/something"));
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
        assertThat(url, is("http://login.localhost/something"));
    }

    @Test
    void findMatchingRedirectUri_usesAntPathMatching() {
        //matches pattern
        String matchingRedirectUri1 = UaaUrlUtils.findMatchingRedirectUri(Collections.singleton("http://matching.redirect/*"), "http://matching.redirect/", null);
        assertThat(matchingRedirectUri1, equalTo("http://matching.redirect/"));

        //matches pattern

        String matchingRedirectUri2 = UaaUrlUtils.findMatchingRedirectUri(Collections.singleton("http://matching.redirect/*"), "http://matching.redirect/anything-but-forward-slash", null);
        assertThat(matchingRedirectUri2, equalTo("http://matching.redirect/anything-but-forward-slash"));

        //does not match pattern, but no fallback
        matchingRedirectUri2 = UaaUrlUtils.findMatchingRedirectUri(Collections.singleton("http://matching.redirect/*"), "http://does.not.match/redirect", null);
        assertThat(matchingRedirectUri2, equalTo("http://does.not.match/redirect"));

        //does not match pattern, but fallback provided
        matchingRedirectUri2 = UaaUrlUtils.findMatchingRedirectUri(Collections.singleton("http://matching.redirect/*"), "http://does.not.match/redirect", "http://fallback.url/redirect");
        assertThat(matchingRedirectUri2, equalTo("http://fallback.url/redirect"));

        String pattern2 = "http://matching.redirect/**";
        String redirect3 = "http://matching.redirect/whatever/you/want";
        String matchingRedirectUri3 = UaaUrlUtils.findMatchingRedirectUri(Collections.singleton(pattern2), redirect3, null);
        assertThat(matchingRedirectUri3, equalTo(redirect3));

        String pattern3 = "http://matching.redirect/?";
        String redirect4 = "http://matching.redirect/t";
        String matchingRedirectUri4 = UaaUrlUtils.findMatchingRedirectUri(Collections.singleton(pattern3), redirect4, null);
        assertThat(matchingRedirectUri4, equalTo(redirect4));

        String redirect5 = "http://non-matching.redirect/two";
        String fallback = "http://fallback.to/this";
        String matchingRedirectUri5 = UaaUrlUtils.findMatchingRedirectUri(Collections.singleton(pattern3), redirect5, fallback);
        assertThat(matchingRedirectUri5, equalTo(fallback));
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
            "http://foo.bar.com:8080, http://foo.bar.com:8080",
            "http://foo.bar.com:8080/**, http://foo.bar.com:8080/app/foo",
            "http://*.bar.com:8080/**, http://foo.bar.com:8080/app/foo",
            "http://*.bar.com*, http://foo.bar.com:80"
    })
    void findMatchingRedirectUri_urlParametersShouldResolveInIncomingUrl(
            String allowedRedirectUrl,
            String incomingRedirectUrl) {
        final String fallbackRedirectUrl = "http://fallback.to/this";
        Set<String> allowedRedirectUrlGlobPatterns = Collections.singleton(allowedRedirectUrl);

        assertEquals(incomingRedirectUrl, UaaUrlUtils.findMatchingRedirectUri(
                allowedRedirectUrlGlobPatterns,
                incomingRedirectUrl,
                fallbackRedirectUrl
        ));
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
            "http://*.bar.com:8080/**, http://attacker.com#foo.bar.com:8080/app/foo"
    })
    void findMatchingRedirectUri_badRedirectUrlShouldResolveInFallbackUrl(
            String allowedRedirectUrl,
            String incomingMaliciousRedirectUrl) {
        final String fallbackRedirectUrl = "http://fallback.to/this";
        Set<String> allowedRedirectUrlGlobPatterns = Collections.singleton(allowedRedirectUrl);

        assertEquals(fallbackRedirectUrl, UaaUrlUtils.findMatchingRedirectUri(
                allowedRedirectUrlGlobPatterns,
                incomingMaliciousRedirectUrl,
                fallbackRedirectUrl
        ));
    }

    @Test
    void addQueryParameter() {
        String url = "http://sub.domain.com";
        String name = "name";
        String value = "value";
        assertEquals("http://sub.domain.com?name=value", UaaUrlUtils.addQueryParameter(url, name, value));
        assertEquals("http://sub.domain.com/?name=value", UaaUrlUtils.addQueryParameter(url + "/", name, value));
        assertEquals("http://sub.domain.com?key=value&name=value", UaaUrlUtils.addQueryParameter(url + "?key=value", name, value));
        assertEquals("http://sub.domain.com?key=value&name=value#frag=fragvalue", UaaUrlUtils.addQueryParameter(url + "?key=value#frag=fragvalue", name, value));
        assertEquals("http://sub.domain.com?name=value#frag=fragvalue", UaaUrlUtils.addQueryParameter(url + "#frag=fragvalue", name, value));
    }

    @Test
    void addFragmentComponent() {
        String url = "http://sub.domain.com";
        String component = "name=value";
        assertEquals("http://sub.domain.com#name=value", UaaUrlUtils.addFragmentComponent(url, component));
    }

    @Test
    void addFragmentComponentToPriorFragment() {
        String url = "http://sub.domain.com#frag";
        String component = "name=value";
        assertEquals("http://sub.domain.com#frag&name=value", UaaUrlUtils.addFragmentComponent(url, component));
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
        assertEquals("http://somezone.localhost:8080", url);
    }

    @Test
    void addSubdomainToUrl_givenUaaUrlAndSubdomain() {
        String url = UaaUrlUtils.addSubdomainToUrl("http://localhost:8080", "somezone");
        assertEquals("http://somezone.localhost:8080", url);
    }

    @Test
    void addSubdomainToUrl_handlesEmptySubdomain() {
        String url = UaaUrlUtils.addSubdomainToUrl("http://localhost:8080", "");
        assertEquals("http://localhost:8080", url);
    }

    @Test
    void addSubdomainToUrl_handlesEmptySubdomain_defaultZone() {
        String url = UaaUrlUtils.addSubdomainToUrl("http://localhost:8080", "");
        assertEquals("http://localhost:8080", url);
    }

    @Test
    void addSudomain_handlesExtraSpaceInSubdomain() {
        String url = UaaUrlUtils.addSubdomainToUrl("http://localhost:8080", " somezone  ");
        assertEquals("http://somezone.localhost:8080", url);
    }

    @Test
    void addSudomain_handlesExtraSpaceInSubdomain_currentZone() {
        String url2 = UaaUrlUtils.addSubdomainToUrl("http://localhost:8080", " somezone2 ");
        assertEquals("http://somezone2.localhost:8080", url2);
    }

    @Test
    void addSubdomain_handlesUnexpectedDotInSubdomain() {
        String url = UaaUrlUtils.addSubdomainToUrl("http://localhost:8080", " somezone. ");
        assertEquals("http://somezone.localhost:8080", url);
    }

    @Test
    void addSubdomain_handlesUnexpectedDotInSubdomain_currentZone() {
        String url2 = UaaUrlUtils.addSubdomainToUrl("http://localhost:8080", " somezone2. ");
        assertEquals("http://somezone2.localhost:8080", url2);
    }

    @Test
    void uriHasMatchingHost() {
        assertTrue(UaaUrlUtils.uriHasMatchingHost("http://test.com/test", "test.com"));
        assertTrue(UaaUrlUtils.uriHasMatchingHost("http://subdomain.test.com/test", "subdomain.test.com"));
        assertTrue(UaaUrlUtils.uriHasMatchingHost("http://1.2.3.4/test", "1.2.3.4"));

        assertFalse(UaaUrlUtils.uriHasMatchingHost(null, "test.com"));
        assertFalse(UaaUrlUtils.uriHasMatchingHost("http://not-test.com/test", "test.com"));
        assertFalse(UaaUrlUtils.uriHasMatchingHost("not-valid-url", "test.com"));
        assertFalse(UaaUrlUtils.uriHasMatchingHost("http://1.2.3.4/test", "test.com"));
        assertFalse(UaaUrlUtils.uriHasMatchingHost("http://test.com/test", "1.2.3.4"));
        assertFalse(UaaUrlUtils.uriHasMatchingHost("http://not.test.com/test", "test.com"));
    }

    @Test
    void getHostForURI() {
        assertThat(UaaUrlUtils.getHostForURI("http://google.com"), is("google.com"));
        assertThat(UaaUrlUtils.getHostForURI("http://subdomain.uaa.com/nowhere"), is("subdomain.uaa.com"));
        assertThrows(IllegalArgumentException.class, () -> UaaUrlUtils.getHostForURI(""));
    }
    
    @Test
    void getSubdomain() {
        assertThat(UaaUrlUtils.getSubdomain(null), is(nullValue()));
        assertThat(UaaUrlUtils.getSubdomain(""), is(""));
        assertThat(UaaUrlUtils.getSubdomain("     "), is("     "));
        assertThat(UaaUrlUtils.getSubdomain("a"), is("a."));
        assertThat(UaaUrlUtils.getSubdomain("    z     "), is("z."));
        assertThat(UaaUrlUtils.getSubdomain("a.b.c.d.e"), is("a.b.c.d.e."));
    }

    @Test
    void validateValidSubdomains() {
         validSubdomains.forEach(testString -> assertTrue(UaaUrlUtils.isValidSubdomain(testString)));
    }

    @Test
    void validateInvalidSubdomains() {
        invalidSubdomains.forEach(testString -> assertFalse(UaaUrlUtils.isValidSubdomain(testString)));
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
        return urls.stream().map(url -> url.replace("http:", "https:")).collect(Collectors.toList());
    }

}
