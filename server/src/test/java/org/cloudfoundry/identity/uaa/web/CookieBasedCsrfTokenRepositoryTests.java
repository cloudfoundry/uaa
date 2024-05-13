/*
 * ******************************************************************************
 *  *     Cloud Foundry
 *  *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *  *
 *  *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  *     You may not use this product except in compliance with the License.
 *  *
 *  *     This product includes a number of subcomponents with
 *  *     separate copyright notices and license terms. Your use of these
 *  *     subcomponents is subject to the terms and conditions of the
 *  *     subcomponent's license, as noted in the LICENSE file.
 *  ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.junit.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.springframework.security.web.csrf.CsrfToken;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.*;

class CookieBasedCsrfTokenRepositoryTests {

    @Test
    public void testGetHeader_and_Parameter_Name() {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        assertEquals(DEFAULT_CSRF_COOKIE_NAME, repo.getParameterName());
        repo.setParameterName("testcookie");
        assertEquals("testcookie", repo.getParameterName());

        assertEquals(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_HEADER_NAME, repo.getHeaderName());
        repo.setHeaderName("testheader");
        assertEquals("testheader", repo.getHeaderName());

        repo.setGenerator(new RandomValueStringGenerator() {
            @Override
            public String generate() {
                return "token-id";
            }
        });

        CsrfToken token = repo.generateToken(new MockHttpServletRequest());
        assertEquals("testheader", token.getHeaderName());
        assertEquals("testcookie", token.getParameterName());
        assertEquals("token-id", token.getToken());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "/uaa"})
    void testSave_and_Load_Token(String contextPath) {
        String expectedCookiePath = contextPath + "/";
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setPathInfo("/login/somepath");
        request.setContextPath(contextPath);
        CsrfToken token = repo.generateToken(request);
        assertTrue("The token is at least 22 characters long.", token.getToken().length() >= 22);
        repo.saveToken(token, request, response);

        Cookie cookie = response.getCookie(token.getParameterName());
        assertNotNull(cookie);
        assertEquals(token.getToken(), cookie.getValue());
        assertEquals(repo.getCookieMaxAge(), cookie.getMaxAge());
        assertNotNull(cookie.getPath());
        assertEquals(expectedCookiePath, cookie.getPath());

        request.setCookies(cookie);

        CsrfToken saved = repo.loadToken(request);
        assertEquals(token.getToken(), saved.getToken());
        assertEquals(token.getHeaderName(), saved.getHeaderName());
        assertEquals(token.getParameterName(), saved.getParameterName());
    }

    @Test
    void testLoad_Token_During_Get() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod(HttpMethod.GET.name());
        request.setCookies(new Cookie(DEFAULT_CSRF_COOKIE_NAME, "should-be-removed"));

        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();

        CsrfToken csrfToken = repo.loadToken(request);
        assertThat(csrfToken, nullValue());
    }

    @Test
    void saveToken_sameSiteIsLax() {
        HttpServletResponse response = saveTokenAndReturnResponse(false, "http");
        assertThat(response.getHeader("Set-Cookie"), containsString("SameSite=Lax"));
    }

    @Test
    void saveToken_sameSiteIsNone() {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        repo.setSameSiteCookies("None");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        CsrfToken token = repo.generateToken(null);
        repo.saveToken(token, request, response);

        assertThat(response.getHeader("Set-Cookie"), containsString("SameSite=None"));
    }

    @Test
    void saveToken_alwaysHttpOnly() {
        Cookie cookie = saveTokenAndReturnCookie(false, "http");
        assertTrue(cookie.isHttpOnly());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void saveToken_usesSecureAttributeForNonTls(boolean secure) {
        Cookie cookie = saveTokenAndReturnCookie(secure, "http");
        assertEquals(secure, cookie.getSecure());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void saveToken_SecureIfRequestIsOverHttps(boolean secure) {
        Cookie cookie = saveTokenAndReturnCookie(secure, "https");
        assertTrue(cookie.getSecure());
    }

    @Test
    public void saveToken_MakeAnExpiredTokenInResponse_whenNoTokenInRequest() {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        repo.saveToken(null, request, response);

        Cookie cookie = response.getCookie("X-Uaa-Csrf");
        assertEquals(0, cookie.getMaxAge());
        assertFalse(cookie.getValue().isEmpty());
    }

    private MockHttpServletResponse saveTokenAndReturnResponse(boolean isSecure, String protocol) {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        repo.setSecure(isSecure);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme(protocol);
        CsrfToken token = repo.generateToken(null);
        MockHttpServletResponse response = new MockHttpServletResponse();
        repo.saveToken(token, request, response);
        return response;
    }

    private Cookie saveTokenAndReturnCookie(boolean isSecure, String protocol) {
        return saveTokenAndReturnResponse(isSecure, protocol).getCookie("X-Uaa-Csrf");
    }
}
