/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class UaaUrlUtilsTest {

    private List<String> invalidWildCardUrls = Arrays.asList("*", "**", "*/**", "**/*", "*/*", "**/**");
    private List<String> invalidHttpWildCardUrls = Arrays.asList(
        "http://*",
        "http://**",
        "http://*/**",
        "http://*/*",
        "http://**/*",
        "http://a*",
        "http://*.com",
        "http://*domain*",
        "http://*domain.com",
        "http://*domain/path",
        "http://local*",
        "*.valid.com/*/with/path**",
        "http://**/path",
        "https://*.*.*.com/*/with/path**",
        "www.*/path",
        "www.invalid.com/*/with/path**",
        "www.*.invalid.com/*/with/path**",
        "http://username:password@*.com",
        "http://username:password@*.com/path"
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
        "http://username:password@some.server.com",
        "http://username:password@some.server.com/path"
    );

    @Before
    public void setUp() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);
    }

    @After
    public void tearDown() throws Exception {
        IdentityZoneHolder.clear();
        RequestContextHolder.setRequestAttributes(null);
    }

    @Test
    public void getParameterMapFromQueryString() {
        String url = "http://localhost:8080/uaa/oauth/authorize?client_id=app-addnew-false4cEsLB&response_type=code&redirect_uri=http%3A%2F%2Fnosuchhostname%3A0%2Fnosuchendpoint";
        Map<String,String[]> map = UaaUrlUtils.getParameterMap(url);
        assertNotNull(map);
        assertEquals("app-addnew-false4cEsLB", map.get("client_id")[0]);
        assertEquals("http://nosuchhostname:0/nosuchendpoint", map.get("redirect_uri")[0]);
    }
    @Test
    public void testGetUaaUrl() throws Exception {
        assertEquals("http://localhost", UaaUrlUtils.getUaaUrl());
    }

    @Test
    public void testGetBaseURL() throws Exception {
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
    public void testGetBaseURLWhenPathMatchesHostname() throws Exception {
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
    public void testGetBaseURLOnLocalhost() throws Exception {
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
    public void test_ZoneAware_UaaUrl() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("id","subdomain");
        IdentityZoneHolder.set(zone);
        assertEquals("http://localhost", UaaUrlUtils.getUaaUrl(""));
        assertEquals("http://subdomain.localhost", UaaUrlUtils.getUaaUrl("",true));
    }


    @Test
    public void testGetUaaUrlWithPath() throws Exception {
        assertEquals("http://localhost/login", UaaUrlUtils.getUaaUrl("/login"));
    }

    @Test
    public void testGetUaaUrlWithZone() throws Exception {
        setIdentityZone("zone1");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("zone1.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        assertEquals("http://zone1.localhost", UaaUrlUtils.getUaaUrl());
    }

    @Test
    public void testGetUaaUrlWithZoneAndPath() throws Exception {
        setIdentityZone("zone1");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("zone1.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        assertEquals("http://zone1.localhost/login", UaaUrlUtils.getUaaUrl("/login"));
    }

    @Test
    public void testGetHost() throws Exception {
        assertEquals("localhost", UaaUrlUtils.getUaaHost());
    }

    @Test
    public void testGetHostWithZone() throws Exception {
        setIdentityZone("zone1");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("zone1.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);

        assertEquals("zone1.localhost", UaaUrlUtils.getUaaHost());
    }

    @Test
    public void testLocalhostPortAndContextPathUrl() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setContextPath("/uaa");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        String url = UaaUrlUtils.getUaaUrl("/something");
        assertThat(url, is("http://localhost:8080/uaa/something"));
    }

    @Test
    public void testSecurityProtocol() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerPort(8443);
        request.setServerName("localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        String url = UaaUrlUtils.getUaaUrl("/something");
        assertThat(url, is("https://localhost:8443/something"));
    }

    @Test
    public void testMultiDomainUrls() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("login.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        String url = UaaUrlUtils.getUaaUrl("/something");
        assertThat(url, is("http://login.localhost/something"));
    }

    @Test
    public void testZonedAndMultiDomainUrls() {
        IdentityZoneHolder.set(MultitenancyFixture.identityZone("testzone1-id", "testzone1"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("testzone1.login.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        String url = UaaUrlUtils.getUaaUrl("/something");
        assertThat(url, is("http://testzone1.login.localhost/something"));
    }

    @Test
    public void testXForwardedPrefixUrls() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("login.localhost");
        request.addHeader("X-Forwarded-Prefix", "/prefix");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        String url = UaaUrlUtils.getUaaUrl("/something");
        assertThat(url, is("http://login.localhost/prefix/something"));
    }

    @Test
    public void findMatchingRedirectUri_usesAntPathMatching() {
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

    @Test
    public void test_add_query_parameter() {
        String url = "http://sub.domain.com";
        String name = "name";
        String value = "value";
        assertEquals("http://sub.domain.com?name=value", UaaUrlUtils.addQueryParameter(url, name, value));
        assertEquals("http://sub.domain.com/?name=value", UaaUrlUtils.addQueryParameter(url+"/", name, value));
        assertEquals("http://sub.domain.com?key=value&name=value", UaaUrlUtils.addQueryParameter(url+"?key=value", name, value));
        assertEquals("http://sub.domain.com?key=value&name=value#frag=fragvalue", UaaUrlUtils.addQueryParameter(url+"?key=value#frag=fragvalue", name, value));
        assertEquals("http://sub.domain.com?name=value#frag=fragvalue", UaaUrlUtils.addQueryParameter(url+"#frag=fragvalue", name, value));
    }

    @Test
    public void test_add_fragment_component() {
        String url = "http://sub.domain.com";
        String component = "name=value";
        assertEquals("http://sub.domain.com#name=value", UaaUrlUtils.addFragmentComponent(url, component));
    }

    @Test
    public void test_add_fragment_component_to_prior_fragment() {
        String url = "http://sub.domain.com#frag";
        String component = "name=value";
        assertEquals("http://sub.domain.com#frag&name=value", UaaUrlUtils.addFragmentComponent(url, component));
    }

    @Test
    public void test_validate_valid_redirect_uri() {
        validateRedirectUri(validUrls, true);
        validateRedirectUri(convertToHttps(validUrls), true);
    }

    @Test
    public void test_validate_invalid_redirect_uri() {
        validateRedirectUri(invalidWildCardUrls, false);
        validateRedirectUri(invalidHttpWildCardUrls, false);
        validateRedirectUri(convertToHttps(invalidHttpWildCardUrls), false);
    }

    private void validateRedirectUri(List<String> urls, boolean result) {
        Map<String, String> failed = getFailedUrls(urls, result);
        if (!failed.isEmpty()) {
            StringBuilder builder = new StringBuilder("\n");
            failed.entrySet().forEach(entry ->
                builder.append(entry.getValue()).append("\n")
            );
            fail(builder.toString());
        }
    }
    private Map<String, String> getFailedUrls(List<String> urls, boolean result) {
        Map<String, String> failed = new LinkedHashMap<>();
        urls.stream().forEach(
            url -> {
                String message = "Assertion failed for " + (result ? "" : "in") + "valid url:" + url;
                if (result != UaaUrlUtils.isValidRegisteredRedirectUrl(url)) {
                    failed.put(url, message);
                }
            }
        );
        return failed;
    }

    private List<String> convertToHttps(List<String> urls) {
        return urls.stream().map(url -> url.replace("http:", "https:")).collect(Collectors.toList());
    }

    private void setIdentityZone(String subdomain) {
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        IdentityZoneHolder.set(zone);
    }
}
