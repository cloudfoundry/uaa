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
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.csrf.CsrfToken;

import java.util.Arrays;
import javax.servlet.http.Cookie;

import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

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
        Cookie cookie = getCookie(false);
        assertTrue(cookie.isHttpOnly());
        assertFalse(cookie.getSecure());
    }

    @Test
    public void csrfCookie_SecureIfHttpsRequired() {
        Cookie cookie = getCookie(true);
        assertTrue(cookie.getSecure());
    }

    @Test
    public void csrfCookie_SecureIfRequestIsOverHttps() {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        MockHttpServletResponse response = new MockHttpServletResponse();
        CsrfToken token = repo.generateToken(request);
        repo.saveToken(token, request, response);
        Cookie cookie = response.getCookie(token.getParameterName());
        assertTrue(cookie.getSecure());
    }

    private Cookie getCookie(boolean isSecure) {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        repo.setSecure(isSecure);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        CsrfToken token = repo.generateToken(request);
        repo.saveToken(token, request, response);

        return response.getCookie(token.getParameterName());
    }
}
