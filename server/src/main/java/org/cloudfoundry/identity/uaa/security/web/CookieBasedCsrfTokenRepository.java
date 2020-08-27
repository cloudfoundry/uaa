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

import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static java.util.Optional.ofNullable;

public class CookieBasedCsrfTokenRepository implements CsrfTokenRepository {

    public static final String DEFAULT_CSRF_HEADER_NAME = "X-CSRF-TOKEN";
    public static final String DEFAULT_CSRF_COOKIE_NAME = "X-Uaa-Csrf";
    public static final int DEFAULT_COOKIE_MAX_AGE = 60 * 60 * 24;

    // 22 characters of the 62-ary codec gives about 131 bits of entropy, 62 ^ 22 ~ 2^ 130.9923
    private RandomValueStringGenerator generator = new RandomValueStringGenerator(22);
    private String parameterName = DEFAULT_CSRF_COOKIE_NAME;
    private String headerName = DEFAULT_CSRF_HEADER_NAME;
    private int cookieMaxAge = DEFAULT_COOKIE_MAX_AGE;
    private boolean secure;

    public int getCookieMaxAge() {
        return cookieMaxAge;
    }

    public void setCookieMaxAge(int cookieMaxAge) {
        this.cookieMaxAge = cookieMaxAge;
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
        if (token==null) {
            token = generateToken(request);
            expire = true;
        }
        Cookie csrfCookie = new Cookie(token.getParameterName(), token.getToken());
        csrfCookie.setHttpOnly(true);
        csrfCookie.setSecure(secure || request.getScheme().equals("https"));
        csrfCookie.setPath(ofNullable(request.getContextPath()).orElse("") + "/");
        if (expire) {
            csrfCookie.setMaxAge(0);
        } else {
            csrfCookie.setMaxAge(getCookieMaxAge());
        }
        response.addCookie(csrfCookie);
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        boolean requiresCsrfProtection = CsrfFilter.DEFAULT_CSRF_MATCHER.matches(request);

        if(requiresCsrfProtection) {
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
