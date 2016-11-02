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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.login.AccountSavingAuthenticationSuccessHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;

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

public class XOAuthAuthenticationFilter implements Filter {

    private static Log logger = LogFactory.getLog(XOAuthAuthenticationFilter.class);

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

        String origin = URIUtil.getName(request.getServletPath());
        String code = request.getParameter("code");
        String redirectUrl = request.getRequestURL().toString();
        XOAuthCodeToken codeToken = new XOAuthCodeToken(code, origin, redirectUrl);
        codeToken.setDetails(new UaaAuthenticationDetails(request));
        try {
            Authentication authentication = xOAuthAuthenticationManager.authenticate(codeToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            ofNullable(successHandler).ifPresent(handler ->
                handler.setSavedAccountOptionCookie(request, response, authentication)
            );
        } catch (Exception ex) {
            logger.debug("XOauth Authentication exception", ex);
            String message = ex.getMessage();
            if(!StringUtils.hasText(message)) {
                message = ex.getClass().getSimpleName();
            }
            String errorMessage = URLEncoder.encode("There was an error when authenticating against the external identity provider: " + message, "UTF-8");
            response.sendRedirect(request.getContextPath() + "/oauth_error?error=" + errorMessage);
            return;
        }
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {

    }
}
