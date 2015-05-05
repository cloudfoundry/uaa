/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */
package org.cloudfoundry.identity.uaa.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Filter which processes and authenticates a client based on
 * parameters client_id and client_secret
 * It sets the authentication to a client only
 * Oauth2Authentication object as that is expected by
 * the LoginAuthenticationManager.
 *
 */
public class ClientParametersAuthenticationFilter implements Filter {

    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";
    private final Log logger = LogFactory.getLog(getClass());

    private AuthenticationManager clientAuthenticationManager;

    private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    public AuthenticationManager getClientAuthenticationManager() {
        return clientAuthenticationManager;
    }

    public void setClientAuthenticationManager(AuthenticationManager clientAuthenticationManager) {
        this.clientAuthenticationManager = clientAuthenticationManager;
    }

    /**
     * @param authenticationEntryPoint the authenticationEntryPoint to set
     */
    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
                    ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        Map<String, String> loginInfo = getCredentials(req);
        String clientId = loginInfo.get(CLIENT_ID);

        try {
            if (loginInfo.isEmpty()) {
                throw new BadCredentialsException("Request does not contain credentials.");
            } else if (clientAuthenticationManager==null || loginInfo.get(CLIENT_ID)==null) {
                logger.debug("Insufficient resources to perform client authentication. AuthMgr:"+
                    clientAuthenticationManager + "; clientId:"+clientId);
                throw new BadCredentialsException("Request does not contain client credentials.");
            } else {
                logger.debug("Located credentials in request, with keys: " + loginInfo.keySet());

                Authentication clientAuth = performClientAuthentication(req, loginInfo, clientId);
                SecurityContextHolder.getContext().setAuthentication(clientAuth);
            }
        } catch (AuthenticationException e) {
            logger.debug("Client Parameter Authentication failed");
            authenticationEntryPoint.commence(req, res, e);
            return;
        }

        chain.doFilter(request, response);
    }

    private Map<String, String> getSingleValueMap(HttpServletRequest request) {
        Map<String, String> map = new HashMap<String, String>();
        @SuppressWarnings("unchecked")
        Map<String, String[]> parameters = request.getParameterMap();
        for (String key : parameters.keySet()) {
            String[] values = parameters.get(key);
            map.put(key, values != null && values.length > 0 ? values[0] : null);
        }
        return map;
    }

    private Collection<String> getScope(HttpServletRequest request) {
        return OAuth2Utils.parseParameterList(request.getParameter("scope"));
    }

    private Authentication performClientAuthentication(HttpServletRequest req, Map<String, String> loginInfo, String clientId) {

        String clientSecret = loginInfo.get(CLIENT_SECRET);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(clientId, clientSecret);
        authentication.setDetails(new UaaAuthenticationDetails(req, clientId));
        try {
            Authentication auth = clientAuthenticationManager.authenticate(authentication);
            if (auth==null || !auth.isAuthenticated()) {
                throw new BadCredentialsException("Client Authentication failed.");
            }
            loginInfo.remove(CLIENT_SECRET);
            AuthorizationRequest authorizationRequest = new AuthorizationRequest(clientId, getScope(req));
            authorizationRequest.setRequestParameters(getSingleValueMap(req));
            authorizationRequest.setApproved(true);
            //must set this to true in order for
            //Authentication.isAuthenticated to return true
            OAuth2Authentication result = new OAuth2Authentication(authorizationRequest.createOAuth2Request(),null);
            result.setAuthenticated(true);
            return result;
        } catch (AuthenticationException e) {
            throw new BadCredentialsException(e.getMessage(), e);
        } catch (Exception e) {
            logger.debug("Unable to authenticate client: " + clientId, e);
            throw new BadCredentialsException(e.getMessage(), e);
        }
    }

    private Map<String, String> getCredentials(HttpServletRequest request) {
        Map<String, String> credentials = new HashMap<String, String>();
        credentials.put(CLIENT_ID, request.getParameter(CLIENT_ID));
        credentials.put(CLIENT_SECRET, request.getParameter(CLIENT_SECRET));
        return credentials;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }

}
