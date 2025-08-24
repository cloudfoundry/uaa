/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.security;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.util.StringUtils;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class CsrfAwareEntryPointAndDeniedHandler implements AccessDeniedHandler, AuthenticationEntryPoint {

    private final LoginUrlAuthenticationEntryPoint notloggedInCsrfEntryPoint;
    private final LoginUrlAuthenticationEntryPoint loggedInCsrfEntryPoint;
    private final LoginUrlAuthenticationEntryPoint loginEntryPoint;

    public CsrfAwareEntryPointAndDeniedHandler(String login, String redirectCsrf, String redirectNotLoggedIn) {
        if (redirectCsrf == null || !redirectCsrf.startsWith("/")) {
            throw new NullPointerException("Invalid CSRF redirect URL, must start with '/'");
        }
        if (login == null || !login.startsWith("/")) {
            throw new NullPointerException("Invalid CSRF redirect URL, must start with '/'");
        }
        if (redirectNotLoggedIn == null || !redirectNotLoggedIn.startsWith("/")) {
            throw new NullPointerException("Invalid login redirect URL, must start with '/'");
        }
        loginEntryPoint = new LoginUrlAuthenticationEntryPoint(login);
        notloggedInCsrfEntryPoint = new LoginUrlAuthenticationEntryPoint(redirectNotLoggedIn);
        loggedInCsrfEntryPoint = new LoginUrlAuthenticationEntryPoint(redirectCsrf) {
            @Override
            public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                super.commence(request, response, authException);
            }
        };
        loggedInCsrfEntryPoint.setUseForward(true);
    }

    public CsrfAwareEntryPointAndDeniedHandler(String redirectCsrf, String redirectNotLoggedIn) {
        this("/login", redirectCsrf, redirectNotLoggedIn);
    }

    protected boolean isUserLoggedIn() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.isAuthenticated() && auth.getPrincipal() instanceof UaaPrincipal;
    }

    protected boolean wantJson(HttpServletRequest request) {
        String accept = request.getHeader("Accept");
        boolean json = false;
        if (StringUtils.hasText(accept)) {
            for (MediaType mediaType : MediaType.parseMediaTypes(accept)) {
                if (mediaType.equals(MediaType.APPLICATION_JSON)) {
                    json = true;
                    break;
                }
            }
        }
        return json;
    }

    protected void internalHandle(HttpServletRequest request,
                                  HttpServletResponse response,
                                  Exception exception) throws IOException, ServletException {

        AuthenticationException authEx = exception instanceof AuthenticationException ae ?
                ae : new InternalAuthenticationServiceException("Access denied.", exception);

        if (wantJson(request)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().append("{\"error\":\"%s\"}".formatted(exception.getMessage()));
        } else {
            LoginUrlAuthenticationEntryPoint entryPoint = getLoginUrlAuthenticationEntryPoint(exception);
            entryPoint.commence(request, response, authEx);
        }
    }

    protected LoginUrlAuthenticationEntryPoint getLoginUrlAuthenticationEntryPoint(Exception exception) {
        if (exception instanceof MissingCsrfTokenException || exception instanceof InvalidCsrfTokenException) {
            if (!isUserLoggedIn()) {
                return notloggedInCsrfEntryPoint;
            } else {
                return loggedInCsrfEntryPoint;
            }
        } else {
            return loginEntryPoint;
        }
    }

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException,
            ServletException {
        request.setAttribute(WebAttributes.ACCESS_DENIED_403, accessDeniedException);
        // if we get any other access denied, we end up here
        internalHandle(request, response, accessDeniedException);
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // if there is insufficient authentication, this will be called
        internalHandle(request, response, authException);
    }
}
