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

import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;

class CookieBasedCsrfTokenRepositoryTests {

    @Test
    void getHeaderAndParameterName() {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        assertThat(repo.getParameterName()).isEqualTo(DEFAULT_CSRF_COOKIE_NAME);
        repo.setParameterName("testcookie");
        assertThat(repo.getParameterName()).isEqualTo("testcookie");

        assertThat(repo.getHeaderName()).isEqualTo(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_HEADER_NAME);
        repo.setHeaderName("testheader");
        assertThat(repo.getHeaderName()).isEqualTo("testheader");

        repo.setGenerator(new RandomValueStringGenerator() {
            @Override
            public String generate() {
                return "token-id";
            }
        });

        CsrfToken token = repo.generateToken(new MockHttpServletRequest());
        assertThat(token.getHeaderName()).isEqualTo("testheader");
        assertThat(token.getParameterName()).isEqualTo("testcookie");
        assertThat(token.getToken()).isEqualTo("token-id");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "/uaa"})
    void saveAndLoadToken(String contextPath) {
        String expectedCookiePath = contextPath + "/";
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setPathInfo("/login/somepath");
        request.setContextPath(contextPath);
        CsrfToken token = repo.generateToken(request);
        assertThat(token.getToken().length()).as("The token is at least 22 characters long.").isGreaterThanOrEqualTo(22);
        repo.saveToken(token, request, response);

        Cookie cookie = response.getCookie(token.getParameterName());
        assertThat(cookie).isNotNull();
        assertThat(cookie.getValue()).isEqualTo(token.getToken());
        assertThat(cookie.getMaxAge()).isEqualTo(repo.getCookieMaxAge());
        assertThat(cookie.getPath()).isNotNull()
                .isEqualTo(expectedCookiePath);

        request.setCookies(cookie);

        CsrfToken saved = repo.loadToken(request);
        assertThat(saved.getToken()).isEqualTo(token.getToken());
        assertThat(saved.getHeaderName()).isEqualTo(token.getHeaderName());
        assertThat(saved.getParameterName()).isEqualTo(token.getParameterName());
    }

    @Test
    void loadTokenDuringGet() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod(HttpMethod.GET.name());
        request.setCookies(new Cookie(DEFAULT_CSRF_COOKIE_NAME, "should-be-removed"));

        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();

        CsrfToken csrfToken = repo.loadToken(request);
        assertThat(csrfToken).isNull();
    }

    @Test
    void saveToken_sameSiteIsLax() {
        HttpServletResponse response = saveTokenAndReturnResponse(false, "http");
        assertThat(response.getHeader("Set-Cookie")).contains("SameSite=Lax");
    }

    @Test
    void saveToken_sameSiteIsNone() {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        repo.setSameSiteCookies("None");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        CsrfToken token = repo.generateToken(null);
        repo.saveToken(token, request, response);

        assertThat(response.getHeader("Set-Cookie")).contains("SameSite=None");
    }

    @Test
    void saveToken_alwaysHttpOnly() {
        Cookie cookie = saveTokenAndReturnCookie(false, "http");
        assertThat(cookie.isHttpOnly()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void saveToken_usesSecureAttributeForNonTls(boolean secure) {
        Cookie cookie = saveTokenAndReturnCookie(secure, "http");
        assertThat(cookie.getSecure()).isEqualTo(secure);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void saveToken_SecureIfRequestIsOverHttps(boolean secure) {
        Cookie cookie = saveTokenAndReturnCookie(secure, "https");
        assertThat(cookie.getSecure()).isTrue();
    }

    @Test
    void saveToken_MakeAnExpiredTokenInResponse_whenNoTokenInRequest() {
        CookieBasedCsrfTokenRepository repo = new CookieBasedCsrfTokenRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        repo.saveToken(null, request, response);

        Cookie cookie = response.getCookie("X-Uaa-Csrf");
        assertThat(cookie.getMaxAge()).isZero();
        assertThat(cookie.getValue()).isNotEmpty();
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
