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
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
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

public class XOAuthAuthenticationFilter implements Filter {


    private final XOAuthAuthenticationManager xOAuthAuthenticationManager;

    public XOAuthAuthenticationFilter(XOAuthAuthenticationManager xOAuthAuthenticationManager) {
        this.xOAuthAuthenticationManager = xOAuthAuthenticationManager;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
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
            chain.doFilter(request, response);
        } catch (Exception ex) {
            String errorMessage = "There was an error when authenticating against the external identity provider: " + ex.getMessage();
            response.sendRedirect(request.getContextPath() + "/oauth_error?error=" + errorMessage);
        }
    }

    @Override
    public void destroy() {

    }
}
