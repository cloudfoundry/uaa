/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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

import lombok.Getter;
import lombok.Setter;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Filter which processes and authenticates a client based on
 * parameters client_id and client_secret
 * It sets the authentication to a client only
 * Oauth2Authentication object as that is expected by
 * the LoginAuthenticationManager.
 */
public abstract class AbstractClientParametersAuthenticationFilter implements Filter {

    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String CLIENT_ASSERTION = "client_assertion";

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    @Setter
    @Getter
    protected AuthenticationManager clientAuthenticationManager;

    @Setter
    protected AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        Map<String, String> loginInfo = getCredentials(req);
        String clientId = loginInfo.get(CLIENT_ID);

        try {
            if (clientId == null) {
                clientId = Optional.ofNullable(loginInfo.get(CLIENT_ASSERTION)).map(JwtClientAuthentication::getClientIdOidcAssertion).orElse(null);
            }
            wrapClientCredentialLogin(req, res, loginInfo, clientId);
        } catch (AuthenticationException ex) {
            logger.debug("Could not authenticate with client credentials.");
            authenticationEntryPoint.commence(req, res, ex);
            return;
        }

        chain.doFilter(req, res);
    }

    public abstract void wrapClientCredentialLogin(HttpServletRequest req, HttpServletResponse res, Map<String, String> loginInfo, String clientId);

    protected void doClientCredentialLogin(HttpServletRequest req, Map<String, String> loginInfo, String clientId) {
        Authentication clientAuth = performClientAuthentication(req, loginInfo, clientId);
        SecurityContextHolder.getContext().setAuthentication(clientAuth);
    }

    private Map<String, String> getSingleValueMap(HttpServletRequest request) {
        Map<String, String> map = new HashMap<>();
        Map<String, String[]> parameters = request.getParameterMap();
        for (Map.Entry<String, String[]> entry : parameters.entrySet()) {
            String[] values = parameters.get(entry.getKey());
            map.put(entry.getKey(), values != null && values.length > 0 ? values[0] : null);
        }
        return map;
    }

    private Collection<String> getScope(HttpServletRequest request) {
        return OAuth2Utils.parseParameterList(request.getParameter("scope"));
    }

    private Authentication performClientAuthentication(HttpServletRequest req, Map<String, String> loginInfo, String clientId) {
        // spring security 6.x requires a credential to be present
        String clientSecret = Optional.ofNullable(loginInfo.get(CLIENT_SECRET)).orElse(UaaStringUtils.EMPTY_STRING);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(clientId, clientSecret);
        authentication.setDetails(new UaaAuthenticationDetails(req, clientId));
        try {
            Authentication auth = clientAuthenticationManager.authenticate(authentication);
            if (auth == null || !auth.isAuthenticated()) {
                throw new BadCredentialsException("Client Authentication failed.");
            }
            loginInfo.remove(CLIENT_SECRET);
            AuthorizationRequest authorizationRequest = new AuthorizationRequest(clientId, getScope(req));
            authorizationRequest.setRequestParameters(getSingleValueMap(req));
            authorizationRequest.setApproved(true);

            if (auth.getDetails() instanceof UaaAuthenticationDetails clientDetails
                    && clientDetails.getAuthenticationMethod() != null) {
                authorizationRequest.setExtensions(Map.of(ClaimConstants.CLIENT_AUTH_METHOD, clientDetails.getAuthenticationMethod()));
            }

            //must set this to true in order for
            //Authentication.isAuthenticated to return true
            OAuth2Authentication result = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);
            result.setAuthenticated(true);
            return result;
        } catch (AuthenticationException e) {
            throw new BadCredentialsException(e.getMessage(), e);
        } catch (Exception e) {
            logger.debug("Unable to authenticate client: {}", UaaStringUtils.getCleanedUserControlString(clientId), e);
            throw new BadCredentialsException(e.getMessage(), e);
        }
    }

    private Map<String, String> getCredentials(HttpServletRequest request) {
        Map<String, String> credentials = new HashMap<>();
        String clientId = request.getParameter(CLIENT_ID);
        credentials.put(CLIENT_ID, clientId);
        credentials.put(CLIENT_SECRET, request.getParameter(CLIENT_SECRET));
        if (clientId == null) {
            credentials.put(CLIENT_ASSERTION, request.getParameter(CLIENT_ASSERTION));
        }
        return credentials;
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }
}
