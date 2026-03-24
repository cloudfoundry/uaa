/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.zone;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter.DEFAULT_ZONE_SUBDOMAIN_PATH;
import static org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter.ZONE_PATH_PREFIX;

class ZonePathContextRewritingFilterTests {

    private ZonePathContextRewritingFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private AtomicReference<HttpServletRequest> requestPassedToChain;

    @BeforeEach
    void setUp() {
        filter = new ZonePathContextRewritingFilter();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        requestPassedToChain = new AtomicReference<>();
    }

    @Test
    void pathWithoutZonePrefix_passesRequestUnchanged() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/login");
        request.setServletPath("/login");  // container would set this; filter passes request as-is

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed).isSameAs(request);
        assertThat(passed.getContextPath()).isEqualTo("/uaa");
        assertThat(passed.getRequestURI()).isEqualTo("/uaa/login");
        assertThat(passed.getServletPath()).isEqualTo("/login");
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isNull();
    }

    @Test
    void pathWithOnlyZ_noTrailingSlash_passesRequestUnchanged() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z");  // does not start with /z/ so not treated as zone path

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
        assertThat(request.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isNull();
    }

    @Test
    void pathWithOnlyZ_prefix_noSubdomain_rejectsWithBadRequest() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/");  // starts with /z/ but no subdomain segment

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        assertThat(requestPassedToChain.get()).isNull();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    }

    @Test
    void pathWithZAndSubdomainButNoSlashAfter_rejectsWithBadRequest() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        assertThat(requestPassedToChain.get()).isNull();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    }

    @Test
    void pathWithEmptySubdomainSegment_rejectsWithBadRequest() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z//login");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        assertThat(requestPassedToChain.get()).isNull();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    }

    @Test
    void pathWithDefaultZonePrefix_withContextPath_rewritesToIncludeZonePathAndDoesNotSetZoneSubdomainFromPath() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa" + ZONE_PATH_PREFIX + DEFAULT_ZONE_SUBDOMAIN_PATH + "/login");
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setScheme("http");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed).isNotSameAs(request);
        assertThat(passed.getContextPath()).isEqualTo("/uaa/z/" + DEFAULT_ZONE_SUBDOMAIN_PATH);
        assertThat(passed.getServletPath()).isEqualTo("/login");
        assertThat(passed.getRequestURI()).isEqualTo("/uaa/z/" + DEFAULT_ZONE_SUBDOMAIN_PATH + "/login");
        assertThat(passed.getPathInfo()).isNull();
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isNull();
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_ORIGINAL_CONTEXT_PATH)).isEqualTo("/uaa");
    }

    @Test
    void pathWithDefaultZonePrefix_withoutContextPath_rewritesToIncludeZonePathAndDoesNotSetZoneSubdomainFromPath() throws ServletException, IOException {
        request.setContextPath("");
        request.setRequestURI(ZONE_PATH_PREFIX + DEFAULT_ZONE_SUBDOMAIN_PATH + "/login");
        request.setServerName("localhost");
        request.setServerPort(8080);

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed).isNotSameAs(request);
        assertThat(passed.getContextPath()).isEqualTo("/z/" + DEFAULT_ZONE_SUBDOMAIN_PATH);
        assertThat(passed.getServletPath()).isEqualTo("/login");
        assertThat(passed.getRequestURI()).isEqualTo("/z/" + DEFAULT_ZONE_SUBDOMAIN_PATH + "/login");
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isNull();
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_ORIGINAL_CONTEXT_PATH)).isEqualTo("");
    }

    @Test
    void pathWithDefaultZonePrefix_DEFAULT_caseInsensitive_rewritesSameAsLowercase() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/" + DEFAULT_ZONE_SUBDOMAIN_PATH.toUpperCase() + "/profile");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getContextPath()).isEqualTo("/uaa/z/" + DEFAULT_ZONE_SUBDOMAIN_PATH);
        assertThat(passed.getServletPath()).isEqualTo("/profile");
        assertThat(passed.getRequestURI()).isEqualTo("/uaa/z/" + DEFAULT_ZONE_SUBDOMAIN_PATH + "/profile");
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isNull();
    }

    @Test
    void pathWithDefaultZonePrefix_trailingSlash_rewritesWithServletPathEmptyAndPathInfoSlash() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa" + ZONE_PATH_PREFIX + DEFAULT_ZONE_SUBDOMAIN_PATH + "/");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getContextPath()).isEqualTo("/uaa/z/" + DEFAULT_ZONE_SUBDOMAIN_PATH);
        assertThat(passed.getServletPath()).isEmpty();
        assertThat(passed.getPathInfo()).isEqualTo("/");
        assertThat(passed.getRequestURI()).isEqualTo("/uaa/z/" + DEFAULT_ZONE_SUBDOMAIN_PATH + "/");
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isNull();
    }

    @Test
    void pathWithZonePrefix_rewritesRequestAndSetsAttribute() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/login");
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setScheme("http");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed).isNotSameAs(request);
        assertThat(passed.getContextPath()).isEqualTo("/uaa/z/myzone");
        assertThat(passed.getServletPath()).isEqualTo("/login");
        assertThat(passed.getRequestURI()).isEqualTo("/uaa/z/myzone/login");
        assertThat(passed.getPathInfo()).isNull();
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isEqualTo("myzone");
    }

    @Test
    void pathWithZonePrefix_trailingSlashOnly_rewritesWithServletPathEmptyAndPathInfoSlash() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getContextPath()).isEqualTo("/uaa/z/myzone");
        assertThat(passed.getServletPath()).isEmpty();
        assertThat(passed.getPathInfo()).isEqualTo("/");
        assertThat(passed.getRequestURI()).isEqualTo("/uaa/z/myzone/");
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isEqualTo("myzone");
    }

    @Test
    void pathWithZonePrefix_multiplePathSegments_rewritesCorrectly() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/oauth/authorize");
        request.setServerName("localhost");
        request.setServerPort(8443);
        request.setScheme("https");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getContextPath()).isEqualTo("/uaa/z/myzone");
        assertThat(passed.getServletPath()).isEqualTo("/oauth/authorize");
        assertThat(passed.getRequestURI()).isEqualTo("/uaa/z/myzone/oauth/authorize");
        assertThat(passed.getPathInfo()).isNull();
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isEqualTo("myzone");
    }

    @Test
    void emptyContextPath_rewritesCorrectly() throws ServletException, IOException {
        request.setContextPath("");
        request.setRequestURI("/z/testzone/login");
        request.setServerName("localhost");
        request.setServerPort(8080);

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getContextPath()).isEqualTo("/z/testzone");
        assertThat(passed.getServletPath()).isEqualTo("/login");
        assertThat(passed.getRequestURI()).isEqualTo("/z/testzone/login");
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isEqualTo("testzone");
    }

    @Test
    void pathWithZonePrefix_Codes_rewritesServletPathToCodes() throws ServletException, IOException {
        request.setContextPath("");
        request.setRequestURI("/z/myzone/Codes");
        request.setServerName("localhost");
        request.setServerPort(8080);

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getContextPath()).isEqualTo("/z/myzone");
        assertThat(passed.getServletPath()).isEqualTo("/Codes");
        assertThat(passed.getRequestURI()).isEqualTo("/z/myzone/Codes");
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isEqualTo("myzone");
    }

    @Test
    void pathWithZonePrefix_Codes_withContextPath_rewritesServletPathToCodes() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/Codes");
        request.setServerName("localhost");
        request.setServerPort(8080);

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getContextPath()).isEqualTo("/uaa/z/myzone");
        assertThat(passed.getServletPath()).isEqualTo("/Codes");
        assertThat(passed.getRequestURI()).isEqualTo("/uaa/z/myzone/Codes");
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isEqualTo("myzone");
    }

    @Test
    void getRequestURL_onWrappedRequest_returnsRewrittenPath() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/foo/login");
        request.setServerName("login.example.com");
        request.setServerPort(443);
        request.setScheme("https");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        StringBuffer url = passed.getRequestURL();
        assertThat(url.toString()).isEqualTo("https://login.example.com/uaa/z/foo/login");
    }

    @Test
    void getRequestURL_withNonStandardPort_includesPort() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/bar/profile");
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setScheme("http");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getRequestURL().toString()).isEqualTo("http://localhost:8080/uaa/z/bar/profile");
    }

    @Test
    void contextPathSingleSlash_withZonePath_normalizesPathAndRewrites() throws ServletException, IOException {
        request.setContextPath("/");
        request.setRequestURI("/z/rootzone/oauth/token");
        request.setServerName("localhost");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getContextPath()).isEqualTo("/z/rootzone");
        assertThat(passed.getServletPath()).isEqualTo("/oauth/token");
        assertThat(passed.getRequestURI()).isEqualTo("/z/rootzone/oauth/token");
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isEqualTo("rootzone");
    }

    @Test
    void pathAfterContextEmpty_normalizedToSlash_noRewrite() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        assertThat(request.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isNull();
    }

    @Test
    void subdomainWithHyphen_rewritesCorrectly() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/my-zone-name/login");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getContextPath()).isEqualTo("/uaa/z/my-zone-name");
        assertThat(passed.getServletPath()).isEqualTo("/login");
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isEqualTo("my-zone-name");
    }

    // --- ZONE_ORIGINAL_CONTEXT_PATH attribute ---

    @Test
    void pathWithZonePrefix_setsZoneOriginalContextPathAttribute() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/login");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_ORIGINAL_CONTEXT_PATH)).isEqualTo("/uaa");
    }

    @Test
    void pathWithZonePrefix_emptyContextPath_setsZoneOriginalContextPathToEmpty() throws ServletException, IOException {
        request.setContextPath("");
        request.setRequestURI("/z/testzone/login");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_ORIGINAL_CONTEXT_PATH)).isEqualTo("");
    }

    @Test
    void pathWithZonePrefix_contextPathSingleSlash_setsZoneOriginalContextPathToSlash() throws ServletException, IOException {
        request.setContextPath("/");
        request.setRequestURI("/z/rootzone/oauth/token");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_ORIGINAL_CONTEXT_PATH)).isEqualTo("/");
    }

    @Test
    void pathWithoutZonePrefix_setsZoneOriginalContextPathToActualContextPath() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/login");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_ORIGINAL_CONTEXT_PATH)).isEqualTo("/uaa");
    }

    // --- Cookie path rewriting (addCookie) ---

    @Test
    void cookieWithPathSlash_whenZonePathRewritten_rewritesToOriginalContextPath() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/login");

        FilterChain chain = (req, res) -> {
            Cookie c = new Cookie("TestCookie", "value");
            c.setPath("/");
            ((HttpServletResponse) res).addCookie(c);
        };
        filter.doFilter(request, response, chain);

        Cookie[] cookies = response.getCookies();
        assertThat(cookies).hasSize(1);
        assertThat(cookies[0].getPath()).isEqualTo("/uaa");
    }

    @Test
    void cookieWithPathOtherThanSlash_whenZonePathRewritten_leavesPathUnchanged() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/login");

        FilterChain chain = (req, res) -> {
            Cookie c = new Cookie("X", "v");
            c.setPath("/uaa/other");
            ((HttpServletResponse) res).addCookie(c);
        };
        filter.doFilter(request, response, chain);

        Cookie[] cookies = response.getCookies();
        assertThat(cookies).hasSize(1);
        assertThat(cookies[0].getPath()).isEqualTo("/uaa/other");
    }

    @Test
    void cookieWithPathNull_whenZonePathRewritten_rewritesToOriginalContextPath() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/login");

        FilterChain chain = (req, res) -> {
            Cookie c = new Cookie("S", "v");
            ((HttpServletResponse) res).addCookie(c);
        };
        filter.doFilter(request, response, chain);

        Cookie[] cookies = response.getCookies();
        assertThat(cookies).hasSize(1);
        assertThat(cookies[0].getPath()).isEqualTo("/uaa");
    }

    @Test
    void noZonePath_withContextPath_rewritesCookiePathToContextPath() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/login");

        FilterChain chain = (req, res) -> {
            Cookie c = new Cookie("A", "b");
            c.setPath("/");
            ((HttpServletResponse) res).addCookie(c);
        };
        filter.doFilter(request, response, chain);

        Cookie[] cookies = response.getCookies();
        assertThat(cookies).hasSize(1);
        assertThat(cookies[0].getPath()).isEqualTo("/uaa");
    }

    @Test
    void emptyOriginalContextPath_cookiePathRemainsSlash() throws ServletException, IOException {
        request.setContextPath("");
        request.setRequestURI("/z/myzone/login");

        FilterChain chain = (req, res) -> {
            Cookie c = new Cookie("C", "d");
            c.setPath("/");
            ((HttpServletResponse) res).addCookie(c);
        };
        filter.doFilter(request, response, chain);

        Cookie[] cookies = response.getCookies();
        assertThat(cookies).hasSize(1);
        assertThat(cookies[0].getPath()).isEqualTo("/");
    }

    @Test
    void originalContextPathSingleSlash_cookiePathRemainsSlash() throws ServletException, IOException {
        request.setContextPath("/");
        request.setRequestURI("/z/rootzone/login");

        FilterChain chain = (req, res) -> {
            Cookie c = new Cookie("K", "v");
            c.setPath("/");
            ((HttpServletResponse) res).addCookie(c);
        };
        filter.doFilter(request, response, chain);

        Cookie[] cookies = response.getCookies();
        assertThat(cookies).hasSize(1);
        assertThat(cookies[0].getPath()).isEqualTo("/");
    }

    @Test
    void multipleCookies_mixedPaths_rewritesOnlySlashPath() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/login");

        FilterChain chain = (req, res) -> {
            HttpServletResponse httpRes = (HttpServletResponse) res;
            Cookie c1 = new Cookie("One", "1");
            c1.setPath("/");
            httpRes.addCookie(c1);
            Cookie c2 = new Cookie("Two", "2");
            c2.setPath("/custom");
            httpRes.addCookie(c2);
        };
        filter.doFilter(request, response, chain);

        Cookie[] cookies = response.getCookies();
        assertThat(cookies).hasSize(2);
        assertThat(cookies[0].getPath()).isEqualTo("/uaa");
        assertThat(cookies[1].getPath()).isEqualTo("/custom");
    }

    // --- Set-Cookie header (addHeader / setHeader) ---

    @Test
    void addHeaderSetCookie_withPathSlash_whenZonePathRewritten_rewritesPathToOriginalContext() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/login");

        FilterChain chain = (req, res) -> ((HttpServletResponse) res).addHeader("Set-Cookie", "MyCookie=val; Path=/; HttpOnly");
        filter.doFilter(request, response, chain);

        String header = response.getHeader("Set-Cookie");
        assertThat(header).contains("Path=/uaa");
        assertThat(header).contains("HttpOnly");
    }

    @Test
    void addHeaderSetCookie_withNoPath_whenZonePathRewritten_addsPathOriginalContext() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/login");

        FilterChain chain = (req, res) -> ((HttpServletResponse) res).addHeader("Set-Cookie", "Session=abc; HttpOnly");
        filter.doFilter(request, response, chain);

        String header = response.getHeader("Set-Cookie");
        assertThat(header).contains("Path=/uaa");
    }

    @Test
    void addHeaderSetCookie_withPathOtherThanSlash_whenZonePathRewritten_leavesPathUnchanged() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/login");

        FilterChain chain = (req, res) -> ((HttpServletResponse) res).addHeader("Set-Cookie", "X=1; Path=/uaa/other");
        filter.doFilter(request, response, chain);

        String header = response.getHeader("Set-Cookie");
        assertThat(header).contains("Path=/uaa/other");
    }

    @Test
    void setHeaderSetCookie_withPathSlash_whenZonePathRewritten_rewritesPathToOriginalContext() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/login");

        FilterChain chain = (req, res) -> ((HttpServletResponse) res).setHeader("Set-Cookie", "Foo=bar; Path=/; Secure");
        filter.doFilter(request, response, chain);

        String header = response.getHeader("Set-Cookie");
        assertThat(header).contains("Path=/uaa");
        assertThat(header).contains("Secure");
    }

    @Test
    void addHeaderSetCookie_ignoredCookieName_leavesPathUnchanged() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/login");

        FilterChain chain = (req, res) -> ((HttpServletResponse) res).addHeader("Set-Cookie", "Current-User=encoded; Path=/; HttpOnly");
        filter.doFilter(request, response, chain);

        String header = response.getHeader("Set-Cookie");
        assertThat(header).contains("Path=/");
        assertThat(header).contains("Current-User=");
    }

    @Test
    void setHeaderSetCookie_ignoredCookieName_leavesPathUnchanged() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/login");

        FilterChain chain = (req, res) -> ((HttpServletResponse) res).setHeader("Set-Cookie", "Current-User=val; Path=/");
        filter.doFilter(request, response, chain);

        String header = response.getHeader("Set-Cookie");
        assertThat(header).contains("Path=/");
    }

    @Test
    void addHeaderSetCookie_withPathSlash_whenNoContextPath_leavesPathSlash() throws ServletException, IOException {
        request.setContextPath("");
        request.setRequestURI("/z/myzone/login");

        FilterChain chain = (req, res) -> ((HttpServletResponse) res).addHeader("Set-Cookie", "A=B; Path=/");
        filter.doFilter(request, response, chain);

        String header = response.getHeader("Set-Cookie");
        assertThat(header).contains("Path=/");
    }

    // --- zones.paths.enabled flag ---

    @Test
    void zonePathsDisabled_zonePathRequest_returns404() throws ServletException, IOException {
        ZonePathContextRewritingFilter disabledFilter = new ZonePathContextRewritingFilter(false);
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/login");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        disabledFilter.doFilter(request, response, chain);

        assertThat(requestPassedToChain.get()).isNull();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_NOT_FOUND);
    }

    @Test
    void zonePathsDisabled_nonZonePathRequest_passesThrough() throws ServletException, IOException {
        ZonePathContextRewritingFilter disabledFilter = new ZonePathContextRewritingFilter(false);
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/login");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        disabledFilter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed).isSameAs(request);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    void zonePathsEnabled_zonePathRequest_rewritesNormally() throws ServletException, IOException {
        ZonePathContextRewritingFilter enabledFilter = new ZonePathContextRewritingFilter(true);
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/login");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        enabledFilter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getContextPath()).isEqualTo("/uaa/z/myzone");
        assertThat(passed.getServletPath()).isEqualTo("/login");
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isEqualTo("myzone");
    }

    @Test
    void defaultConstructor_zonePathsEnabled() throws ServletException, IOException {
        request.setContextPath("/uaa");
        request.setRequestURI("/uaa/z/myzone/login");

        FilterChain chain = (req, res) -> requestPassedToChain.set((HttpServletRequest) req);
        filter.doFilter(request, response, chain);

        HttpServletRequest passed = requestPassedToChain.get();
        assertThat(passed.getContextPath()).isEqualTo("/uaa/z/myzone");
        assertThat(passed.getAttribute(ZonePathContextRewritingFilter.ZONE_SUBDOMAIN_FROM_PATH)).isEqualTo("myzone");
    }
}