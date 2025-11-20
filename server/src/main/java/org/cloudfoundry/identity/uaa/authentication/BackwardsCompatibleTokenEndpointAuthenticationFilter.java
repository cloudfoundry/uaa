/*******************************************************************************
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
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthCodeToken;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;

/**
 * Provides an implementation that sets the UserAuthentication
 * prior to createAuthorizatioRequest is called.
 * Backwards compatible with Spring Security Oauth2 v1
 * This is a copy of the TokenEndpointAuthenticationFilter from Spring Security Oauth2 v2, but made to work with UAA
 *
 */
public class BackwardsCompatibleTokenEndpointAuthenticationFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(BackwardsCompatibleTokenEndpointAuthenticationFilter.class);

    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    private final AuthenticationManager authenticationManager;

    private final OAuth2RequestFactory oAuth2RequestFactory;

    private final SAMLProcessingFilter samlAuthenticationFilter;

    private final ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager;

    public BackwardsCompatibleTokenEndpointAuthenticationFilter(AuthenticationManager authenticationManager,
                                                                OAuth2RequestFactory oAuth2RequestFactory) {
        this(authenticationManager, oAuth2RequestFactory, null, null);
    }
    /**
     * @param authenticationManager an AuthenticationManager for the incoming request
     */
    public BackwardsCompatibleTokenEndpointAuthenticationFilter(AuthenticationManager authenticationManager,
                                                                OAuth2RequestFactory oAuth2RequestFactory,
                                                                SAMLProcessingFilter samlAuthenticationFilter,
                                                                ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager) {
        super();
        this.authenticationManager = authenticationManager;
        this.oAuth2RequestFactory = oAuth2RequestFactory;
        this.samlAuthenticationFilter = samlAuthenticationFilter;
        this.externalOAuthAuthenticationManager = externalOAuthAuthenticationManager;
    }

    /**
     * An authentication entry point that can handle unsuccessful authentication. Defaults to an
     * {@link OAuth2AuthenticationEntryPoint}.
     *
     * @param authenticationEntryPoint the authenticationEntryPoint to set
     */
    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    /**
     * A source of authentication details for requests that result in authentication.
     *
     * @param authenticationDetailsSource the authenticationDetailsSource to set
     */
    public void setAuthenticationDetailsSource(
        AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
        ServletException {
        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        try {
            Authentication userAuthentication = attemptTokenAuthentication(request, response);

            if (userAuthentication != null) {
                Authentication clientAuth = SecurityContextHolder.getContext().getAuthentication();
                if (clientAuth == null) {
                    throw new BadCredentialsException(
                        "No client authentication found. Remember to put a filter upstream of the TokenEndpointAuthenticationFilter.");
                }

                Map<String, String> map = getSingleValueMap(request);
                map.put(OAuth2Utils.CLIENT_ID, clientAuth.getName());

                SecurityContextHolder.getContext().setAuthentication(userAuthentication);
                AuthorizationRequest authorizationRequest = oAuth2RequestFactory.createAuthorizationRequest(map);

                if (clientAuth.isAuthenticated()) {
                    // Ensure the OAuth2Authentication is authenticated
                    authorizationRequest.setApproved(true);
                }

                OAuth2Request storedOAuth2Request = oAuth2RequestFactory.createOAuth2Request(authorizationRequest);

                SecurityContextHolder
                    .getContext()
                    .setAuthentication(new OAuth2Authentication(storedOAuth2Request, userAuthentication));

                onSuccessfulAuthentication(request, response, userAuthentication);
            }
        } catch (AuthenticationException failed) {
            logger.debug("Authentication request failed: " + failed.getMessage());
            onUnsuccessfulAuthentication(request, response, failed);
            authenticationEntryPoint.commence(request, response, failed);
            return;
        } catch (OAuth2Exception failed) {
            String message = failed.getMessage();
            logger.debug("Authentication request failed with Oauth exception: " + message);
            InsufficientAuthenticationException  ex = new InsufficientAuthenticationException (message, failed);
            onUnsuccessfulAuthentication(request, response, ex);
            authenticationEntryPoint.commence(request, response, ex);
            return;
        }

        chain.doFilter(request, response);
    }

    private Map<String, String> getSingleValueMap(HttpServletRequest request) {
        Map<String, String> map = new HashMap<String, String>();
        Map<String, String[]> parameters = request.getParameterMap();
        for (String key : parameters.keySet()) {
            String[] values = parameters.get(key);
            map.put(key, values != null && values.length > 0 ? values[0] : null);
        }
        return map;
    }

    protected void onSuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response,
                                              Authentication authResult) {
    }

    protected void onUnsuccessfulAuthentication(HttpServletRequest request,
                                                HttpServletResponse response,
                                                AuthenticationException failed) {
        SecurityContextHolder.clearContext();
    }

    /**
     * If the incoming request contains user credentials in headers or parameters then extract them here into an
     * Authentication token that can be validated later. This implementation only recognises password grant requests and
     * extracts the username and password.
     *
     * @param request the incoming request, possibly with user credentials
     * @return an authentication for validation (or null if there is no further authentication)
     */
    protected Authentication extractCredentials(HttpServletRequest request) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        UsernamePasswordAuthenticationToken credentials = new UsernamePasswordAuthenticationToken(username, password);
        credentials.setDetails(authenticationDetailsSource.buildDetails(request));
        return credentials;
    }

    protected Authentication attemptTokenAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String grantType = request.getParameter("grant_type");
        logger.debug("Processing token user authentication for grant:"+grantType);
        Authentication authResult = null;
        if (GRANT_TYPE_PASSWORD.equals(grantType)) {
            Authentication credentials = extractCredentials(request);
            logger.debug("Authentication credentials found password grant for '" + credentials.getName() + "'");
            authResult = authenticationManager.authenticate(credentials);

            if (authResult != null && authResult.isAuthenticated() && authResult instanceof UaaAuthentication) {
                UaaAuthentication uaaAuthentication = (UaaAuthentication) authResult;
                if (SessionUtils.isPasswordChangeRequired(request.getSession())) {
                    throw new PasswordChangeRequiredException(uaaAuthentication, "password change required");
                }
            }

            return authResult;
        } else if (GRANT_TYPE_SAML2_BEARER.equals(grantType)) {
            logger.debug(GRANT_TYPE_SAML2_BEARER +" found. Attempting authentication with assertion");
            String assertion = request.getParameter("assertion");
            if (assertion != null && samlAuthenticationFilter != null) {
                logger.debug("Attempting SAML authentication for token endpoint.");
                authResult = samlAuthenticationFilter.attemptAuthentication(request, response);
            } else {
                logger.debug("No assertion or filter, not attempting SAML authentication for token endpoint.");
                throw new InsufficientAuthenticationException("SAML Assertion is missing");
            }
        }/* else if (GRANT_TYPE_JWT_BEARER.equals(grantType)) {
            logger.debug(GRANT_TYPE_JWT_BEARER +" found. Attempting authentication with assertion");
            String assertion = request.getParameter("assertion");
            if (assertion != null && externalOAuthAuthenticationManager != null) {
                logger.debug("Attempting OIDC JWT authentication for token endpoint.");
                ExternalOAuthCodeToken token = new ExternalOAuthCodeToken(null, null, null, assertion, null, null);
                token.setRequestContextPath(getContextPath(request));
                authResult = externalOAuthAuthenticationManager.authenticate(token);
            } else {
                logger.debug("No assertion or authentication manager, not attempting JWT bearer authentication for token endpoint.");
                throw new InsufficientAuthenticationException("Assertion is missing");
            }
        }*/
        if (authResult != null && authResult.isAuthenticated()) {
            logger.debug("Authentication success: " + authResult.getName());
            return authResult;
        }
        return null;
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }

    private String getContextPath(HttpServletRequest request) {
        StringBuffer requestURL = request.getRequestURL();
        return requestURL.substring(0, requestURL.length() - request.getServletPath().length());
    }
}
