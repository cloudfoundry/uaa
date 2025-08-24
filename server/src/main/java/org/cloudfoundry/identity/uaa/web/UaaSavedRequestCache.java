/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.web;


import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.UrlUtils;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.util.StringUtils.hasText;

public class UaaSavedRequestCache extends HttpSessionRequestCache implements Filter {

    public UaaSavedRequestCache() {
        setMatchingRequestParameterName(null);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        //we want to be able to capture the parameter on posts
        if (shouldSaveFormRedirectParameter(request) && notAuthenticated()) {
            saveClientRedirect(request, request.getParameter(FORM_REDIRECT_PARAMETER));
        }
        chain.doFilter(request, res);
    }

    public boolean notAuthenticated() {
        return SecurityContextHolder.getContext().getAuthentication() == null ||
                !SecurityContextHolder.getContext().getAuthentication().isAuthenticated();
    }

    @Override
    public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
        if (shouldSaveFormRedirectParameter(request)) {
            saveClientRedirect(request, request.getParameter(FORM_REDIRECT_PARAMETER));
        } else if (GET.name().equals(request.getMethod())) {
            saveClientRedirect(request, UrlUtils.buildFullRequestUrl(request));
        } else {
            //backwards compatible requests
            super.saveRequest(request, response);
        }
    }

    public void saveClientRedirect(HttpServletRequest request, String redirectUrl) {
        SessionUtils.setSavedRequestSession(request.getSession(true),
                new ClientRedirectSavedRequest(request, redirectUrl));
    }

    protected boolean shouldSaveFormRedirectParameter(HttpServletRequest request) {
        String formRedirect = request.getParameter(FORM_REDIRECT_PARAMETER);
        if (!HttpMethod.POST.name().equals(request.getMethod())) {
            return false;
        }
        if (UaaStringUtils.isEmpty(formRedirect)) {
            return false;
        }
        if (!UaaUrlUtils.uriHasMatchingHost(formRedirect, request.getServerName())) {
            return false;
        }
        if (hasSavedRequest(request)) {
            return false;
        }

        return POST.name().equals(request.getMethod());
    }

    protected static boolean hasSavedRequest(HttpServletRequest request) {
        return getSavedRequest(request) != null;
    }

    protected static SavedRequest getSavedRequest(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session == null ? null : SessionUtils.getSavedRequestSession(session);
    }

    @Override
    public void init(FilterConfig filterConfig) {

    }

    @Override
    public void destroy() {

    }

    public static class ClientRedirectSavedRequest extends DefaultSavedRequest {

        private final String redirectUrl;
        private final Map<String, String[]> parameters;

        public ClientRedirectSavedRequest(HttpServletRequest request, String redirectUrl) {
            super(request, ServletRequest::getServerPort);
            this.redirectUrl = redirectUrl;
            parameters = Collections.unmodifiableMap(UaaUrlUtils.getParameterMap(redirectUrl));
        }

        @Override
        public String getRedirectUrl() {
            return redirectUrl;
        }

        @Override
        public List<Cookie> getCookies() {
            return Collections.emptyList();
        }

        @Override
        public String getMethod() {
            return GET.name();
        }

        @Override
        public List<String> getHeaderValues(String name) {
            return Collections.emptyList();
        }

        @Override
        public Collection<String> getHeaderNames() {
            return Collections.emptyList();
        }

        @Override
        public List<Locale> getLocales() {
            return Collections.emptyList();
        }

        @Override
        public String[] getParameterValues(String name) {
            return parameters.get(name);
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            return parameters;
        }

        @Override
        public Collection<String> getParameterNames() {
            return parameters.keySet();
        }

        @Override
        public boolean doesRequestMatch(HttpServletRequest request, PortResolver portResolver) {
            boolean result = UrlUtils.buildFullRequestUrl(request).equals(redirectUrl);
            String formRedirect = request.getParameter(FORM_REDIRECT_PARAMETER);
            if (!result &&
                    POST.name().equals(request.getMethod()) &&
                    hasText(formRedirect)) {
                //we received a form parameter
                result = formRedirect.equals(getRedirectUrl());
            }
            return result;
        }
    }


}
