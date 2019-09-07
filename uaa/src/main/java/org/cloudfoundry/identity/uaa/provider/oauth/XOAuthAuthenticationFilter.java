/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.oauth;

import org.apache.commons.httpclient.util.URIUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.login.AccountSavingAuthenticationSuccessHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

public class XOAuthAuthenticationFilter implements Filter {

    private static Logger logger = LoggerFactory.getLogger(XOAuthAuthenticationFilter.class);

    private final XOAuthAuthenticationManager xOAuthAuthenticationManager;
    private final AccountSavingAuthenticationSuccessHandler successHandler;

    public XOAuthAuthenticationFilter(XOAuthAuthenticationManager xOAuthAuthenticationManager, AccountSavingAuthenticationSuccessHandler successHandler) {
        this.xOAuthAuthenticationManager = xOAuthAuthenticationManager;
        this.successHandler = successHandler;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws  IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        if (containsCredentials(request)) {
            if (authenticationWasSuccessful(request, response)) {
                chain.doFilter(request, response);
            }
        } else {
            request.getRequestDispatcher("/login_implicit").forward(request, response);
        }
    }

    public boolean containsCredentials(HttpServletRequest request) {
        String code = request.getParameter("code");
        String idToken = request.getParameter("id_token");
        String accessToken = request.getParameter("access_token");
        String signedRequest = request.getParameter("signed_request");
        return hasText(code) || hasText(idToken) || hasText(accessToken) || hasText(signedRequest);
    }

    public boolean authenticationWasSuccessful(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String origin = URIUtil.getName(String.valueOf(request.getRequestURL()));
        String code = request.getParameter("code");
        String idToken = request.getParameter("id_token");
        String accessToken = request.getParameter("access_token");
        String signedRequest = request.getParameter("signed_request");

        String redirectUrl = request.getRequestURL().toString();
        XOAuthCodeToken codeToken = new XOAuthCodeToken(code,
                                                        origin,
                                                        redirectUrl,
                                                        idToken,
                                                        accessToken,
                                                        signedRequest,
                                                        new UaaAuthenticationDetails(request));
        try {
            Authentication authentication = xOAuthAuthenticationManager.authenticate(codeToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            ofNullable(successHandler).ifPresent(handler ->
                handler.setSavedAccountOptionCookie(request, response, authentication)
            );
        } catch (Exception ex) {
            logger.error("XOauth Authentication exception", ex);
            String message = ex.getMessage();
            if(!hasText(message)) {
                message = ex.getClass().getSimpleName();
            }
            String errorMessage = URLEncoder.encode("There was an error when authenticating against the external identity provider: " + message, "UTF-8");
            response.sendRedirect(request.getContextPath() + "/oauth_error?error=" + errorMessage);
            return false;
        }
        return true;
    }

    @Override
    public void destroy() {

    }
}
