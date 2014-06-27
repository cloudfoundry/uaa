/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.authentication.manager;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * The filter authenticates token requests from trusted clients.
 * It authenticates the request based on the username only and
 * the fact that the requesting client is trusted.
 * 
 * Must be preceded by an OAuth2AuthenticationProcessingFilter
 * to authenticate the client.
 * 
 * @author jdsa
 * 
 */
public class LoginAuthenticationFilter implements Filter {

    private List<String> parameterNames = Collections.emptyList();

    private static final Log logger = LogFactory.getLog(LoginAuthenticationFilter.class);

    private ObjectMapper mapper = new ObjectMapper();

    private final AuthenticationManager authenticationManager;

    private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    private final ClientDetailsService clientDetailsService;

    public LoginAuthenticationFilter(AuthenticationManager authenticationManager,
                    ClientDetailsService clientDetailsService) {
        super();
        this.authenticationManager = authenticationManager;
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
                    ServletException {

        final boolean debug = logger.isDebugEnabled();
        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        try {
            Authentication credentials = extractCredentials(request);

            if (credentials != null) {

                if (debug) {
                    logger.debug("Authentication credentials found for '" + credentials.getName() + "'");
                }

                Authentication authResult = authenticationManager.authenticate(credentials);

                if (authResult==null) {
                    throw new BadCredentialsException("Invalid user credentials");
                }

                if (debug) {
                    logger.debug("Authentication success: " + authResult.getName());
                }

                Authentication requestingPrincipal = SecurityContextHolder.getContext().getAuthentication();
                if (requestingPrincipal == null) {
                    throw new BadCredentialsException(
                                    "No client authentication found. Remember to put a filter upstream of the LoginAuthenticationFilter.");
                }

                String clientId = request.getParameter("client_id");
                if (null == clientId) {
                    logger.error("No client_id in the request");
                    throw new BadCredentialsException("No client_id in the request");
                }

                // Check that the client exists
                ClientDetails authenticatingClient = null;
                try {
                    authenticatingClient = clientDetailsService.loadClientByClientId(clientId);
                } catch (NoSuchClientException x) {
                    //pass on so we can throw BadCredentialsException
                }
                if (authenticatingClient == null) {
                    throw new BadCredentialsException("No client " + clientId + " found");
                }

                DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(
                                getSingleValueMap(request), null, authenticatingClient.getClientId(), getScope(request));
                if (requestingPrincipal.isAuthenticated()) {
                    // Ensure the OAuth2Authentication is authenticated
                    authorizationRequest.setApproved(true);
                }

                SecurityContextHolder.getContext().setAuthentication(
                                new OAuth2Authentication(authorizationRequest, authResult));

                onSuccessfulAuthentication(request, response, authResult);

            }

        } catch (AuthenticationException failed) {
            SecurityContextHolder.clearContext();

            if (debug) {
                logger.debug("Authentication request for failed: " + failed);
            }

            onUnsuccessfulAuthentication(request, response, failed);

            authenticationEntryPoint.commence(request, response, failed);

            return;
        }

        chain.doFilter(request, response);
    }

    protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                    Authentication authResult) throws IOException {
    }

    protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                    AuthenticationException failed) throws IOException {
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

    /**
     * If the incoming request contains user credentials in headers or
     * parameters then extract them here into an
     * Authentication token that can be validated later. This implementation
     * only recognizes password grant requests for
     * users that have been previously authenticated.
     * 
     * @param request the incoming request, possibly with user credentials
     * @return an authentication for validation (or null if there is no further
     *         authentication)
     */
    protected Authentication extractCredentials(HttpServletRequest request) {
        String grantType = request.getParameter("grant_type");
        if (grantType != null && grantType.equals("password")) {
            Map<String, String> loginInfo = getCredentials(request);
            AuthzAuthenticationRequest result = new AuthzAuthenticationRequest(loginInfo, new UaaAuthenticationDetails(
                            request));
            return result;
        }
        return null;
    }

    private Map<String, String> getCredentials(HttpServletRequest request) {
        Map<String, String> credentials = new HashMap<String, String>();

        for (String paramName : parameterNames) {
            String value = request.getParameter(paramName);
            if (value != null) {
                if (value.startsWith("{")) {
                    try {
                        Map<String, String> jsonCredentials = mapper.readValue(value,
                                        new TypeReference<Map<String, String>>() {
                                        });
                        credentials.putAll(jsonCredentials);
                    } catch (IOException e) {
                        logger.warn("Unknown format of value for request param: " + paramName + ". Ignoring.");
                    }
                }
                else {
                    credentials.put(paramName, value);
                }
            }
        }

        return credentials;
    }

    public void setParameterNames(List<String> parameterNames) {
        this.parameterNames = parameterNames;
    }

    /**
     * An authentication entry point that can handle unsuccessful
     * authentication. Defaults to an {@link OAuth2AuthenticationEntryPoint}.
     * 
     * @param authenticationEntryPoint the authenticationEntryPoint to set
     */
    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }
}
