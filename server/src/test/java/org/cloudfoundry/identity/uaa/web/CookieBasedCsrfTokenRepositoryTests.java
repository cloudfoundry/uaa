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
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.csrf.CsrfToken;

import javax.servlet.http.Cookie;
import java.util.Arrays;

import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.*;

public class CookieBasedCsrfTokenRepositoryTests {

    @Test
    public void testGetHeader_and_Parameter_Name() {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        assertEquals(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, repo.getParameterName());
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

    @Test
    public void testSave_and_Load_Token() {
        for (String contextPath : Arrays.asList("", "/uaa")) {
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
            assertTrue(cookie.isHttpOnly());
            assertThat(response.getHeader("Set-Cookie"), containsString("SameSite=Lax"));
            assertEquals(repo.getCookieMaxAge(), cookie.getMaxAge());
            assertNotNull(cookie.getPath());
            assertEquals(expectedCookiePath, cookie.getPath());

            request.setCookies(cookie);

            CsrfToken saved = repo.loadToken(request);
            assertEquals(token.getToken(), saved.getToken());
            assertEquals(token.getHeaderName(), saved.getHeaderName());
            assertEquals(token.getParameterName(), saved.getParameterName());
        }
    }

    @Test
    public void testLoad_Token_During_Get() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod(HttpMethod.GET.name());
        request.setCookies(new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "should-be-removed"));

        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();

        CsrfToken csrfToken = repo.loadToken(request);
        assertThat(csrfToken, nullValue());
    }

    @Test
    public void csrfCookie_alwaysHttpOnly() {
        Cookie cookie = getCookie(false, "http");
        assertTrue(cookie.isHttpOnly());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void csrfCookie_usesSecureAttributeForNonTls(boolean secure) {
        Cookie cookie = getCookie(secure, "http");
        assertEquals(secure, cookie.getSecure());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    public void csrfCookie_SecureIfRequestIsOverHttps(boolean secure) {
        Cookie cookie = getCookie(secure, "https");
        assertTrue(cookie.getSecure());
    }

    private Cookie getCookie(boolean isSecure, String protocol) {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        repo.setSecure(isSecure);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme(protocol);
        CsrfToken token = repo.generateToken(null);
        MockHttpServletResponse response = new MockHttpServletResponse();
        repo.saveToken(token, request, response);

        return response.getCookie(token.getParameterName());
    }
}
