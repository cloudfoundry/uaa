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

package org.cloudfoundry.identity.uaa.security.web;

import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.apache.tomcat.util.http.SameSiteCookies;
import org.cloudfoundry.identity.uaa.UaaProperties;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static java.util.Optional.ofNullable;
import static org.springframework.http.HttpHeaders.SET_COOKIE;

//TODO create XOR tokens in the future
@Component
public class CookieBasedCsrfTokenRepository implements CsrfTokenRepository {

    public static final String DEFAULT_CSRF_HEADER_NAME = "X-CSRF-TOKEN";
    public static final String DEFAULT_CSRF_COOKIE_NAME = "X-Uaa-Csrf";
    public static final int DEFAULT_COOKIE_MAX_AGE = 60 * 60 * 24;
    private final Rfc6265CookieProcessor rfc6265CookieProcessor = new Rfc6265CookieProcessor();

    // 22 characters of the 62-ary codec gives about 131 bits of entropy, 62 ^ 22 ~ 2^ 130.9923
    private RandomValueStringGenerator generator = new RandomValueStringGenerator(22);
    private String parameterName = DEFAULT_CSRF_COOKIE_NAME;
    private String headerName = DEFAULT_CSRF_HEADER_NAME;
    private int cookieMaxAge = DEFAULT_COOKIE_MAX_AGE;
    private boolean secure;

    public CookieBasedCsrfTokenRepository() {
        rfc6265CookieProcessor.setSameSiteCookies("Lax");
    }

    @Autowired
    public CookieBasedCsrfTokenRepository(UaaProperties.RootLevel properties, Environment environment) {
        this();
        this.secure = properties.require_https();
    }

    public int getCookieMaxAge() {
        return cookieMaxAge;
    }

    public void setCookieMaxAge(int cookieMaxAge) {
        this.cookieMaxAge = cookieMaxAge;
    }

    public SameSiteCookies getSameSiteCookies() {
        return rfc6265CookieProcessor.getSameSiteCookies();
    }

    public void setSameSiteCookies(String sameSiteCookies) {
        rfc6265CookieProcessor.setSameSiteCookies(sameSiteCookies);
    }

    public String getHeaderName() {
        return headerName;
    }

    public void setHeaderName(String headerName) {
        this.headerName = headerName;
    }

    public String getParameterName() {
        return parameterName;
    }

    public void setParameterName(String parameterName) {
        this.parameterName = parameterName;
    }

    public void setGenerator(RandomValueStringGenerator generator) {
        this.generator = generator;
    }

    public RandomValueStringGenerator getGenerator() {
        return generator;
    }

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        String token = generator.generate();
        return new DefaultCsrfToken(getHeaderName(), getParameterName(), token);
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        boolean expire = false;
        if (token == null) {
            token = generateToken(request);
            expire = true;
        }
        Cookie csrfCookie = new Cookie(token.getParameterName(), token.getToken());
        csrfCookie.setHttpOnly(true);
        csrfCookie.setSecure(secure || "https".equals(request.getScheme()));
        csrfCookie.setPath(ofNullable(request.getContextPath()).orElse("") + "/");
        if (expire) {
            csrfCookie.setMaxAge(0);
        } else {
            csrfCookie.setMaxAge(getCookieMaxAge());
        }
        String headerValue = rfc6265CookieProcessor.generateHeader(csrfCookie, request);
        response.addHeader(SET_COOKIE, headerValue);
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        boolean requiresCsrfProtection = CsrfFilter.DEFAULT_CSRF_MATCHER.matches(request);

        if (requiresCsrfProtection) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : request.getCookies()) {
                    if (getParameterName().equals(cookie.getName())) {
                        return new DefaultCsrfToken(getHeaderName(), getParameterName(), cookie.getValue());
                    }
                }
            }
        }
        return null;
    }

    public boolean isSecure() {
        return secure;
    }

    public void setSecure(boolean secure) {
        this.secure = secure;
    }
}
