/*
 * *****************************************************************************
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

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthCodeToken;
import org.cloudfoundry.identity.uaa.provider.oauth.TokenExchangeData;
import org.cloudfoundry.identity.uaa.provider.saml.Saml2BearerGrantAuthenticationConverter;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.UaaSecurityContextUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_TYPE_ACCESS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_TYPE_ID;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.hasText;

/**
 * Provides an implementation that sets the UserAuthentication
 * prior to createAuthorizationRequest is called.
 * Backwards compatible with Spring Security Oauth2 v1
 * This is a copy of the TokenEndpointAuthenticationFilter from Spring Security Oauth2 v2, but made to work with UAA
 */
@Slf4j
public class BackwardsCompatibleTokenEndpointAuthenticationFilter implements Filter {
    public static final String DEFAULT_FILTER_PROCESSES_URI = "/oauth/token/alias/{{registrationId}}";
    private final AuthenticationManager tokenExchangeAuthenticationManager;

    /**
     * A source of authentication details for requests that result in authentication.
     */
    @Setter
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    /**
     * An authentication entry point that can handle unsuccessful authentication.
     * Defaults to an {@link OAuth2AuthenticationEntryPoint}.
     */
    @Setter
    private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    private final AuthenticationManager authenticationManager;

    private final OAuth2RequestFactory oAuth2RequestFactory;

    private final Saml2BearerGrantAuthenticationConverter saml2BearerGrantAuthenticationConverter;

    private final ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager;

    private final AntPathRequestMatcher requestMatcher;

    public BackwardsCompatibleTokenEndpointAuthenticationFilter(AuthenticationManager authenticationManager,
            OAuth2RequestFactory oAuth2RequestFactory) {
        this(DEFAULT_FILTER_PROCESSES_URI, authenticationManager, oAuth2RequestFactory, null, null, null);
    }

    public BackwardsCompatibleTokenEndpointAuthenticationFilter(
            AuthenticationManager authenticationManager,
            OAuth2RequestFactory oAuth2RequestFactory,
            Saml2BearerGrantAuthenticationConverter saml2BearerGrantAuthenticationConverter,
            ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager,
            AuthenticationManager tokenExchangeAuthenticationManager) {
        this(
                DEFAULT_FILTER_PROCESSES_URI,
                authenticationManager,
                oAuth2RequestFactory,
                saml2BearerGrantAuthenticationConverter,
                externalOAuthAuthenticationManager,
                tokenExchangeAuthenticationManager
        );
    }

    public BackwardsCompatibleTokenEndpointAuthenticationFilter(
            String requestMatcherUrl,
            AuthenticationManager authenticationManager,
            OAuth2RequestFactory oAuth2RequestFactory,
            Saml2BearerGrantAuthenticationConverter saml2BearerGrantAuthenticationConverter,
            ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager,
            AuthenticationManager tokenExchangeAuthenticationManager) {
        super();
        Assert.isTrue(requestMatcherUrl.contains("{registrationId}"),
                "filterProcessesUrl must contain a {registrationId} match variable");
        requestMatcher = new AntPathRequestMatcher(requestMatcherUrl);

        this.authenticationManager = authenticationManager;
        this.oAuth2RequestFactory = oAuth2RequestFactory;
        this.saml2BearerGrantAuthenticationConverter = saml2BearerGrantAuthenticationConverter;
        this.externalOAuthAuthenticationManager = externalOAuthAuthenticationManager;
        this.tokenExchangeAuthenticationManager = tokenExchangeAuthenticationManager;
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
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

                // seems to be overwritten with new OAuth2Authentication below
                SecurityContextHolder.getContext().setAuthentication(userAuthentication);
                AuthorizationRequest authorizationRequest = oAuth2RequestFactory.createAuthorizationRequest(map);

                if (clientAuth.isAuthenticated()) {
                    // Ensure the OAuth2Authentication is authenticated
                    authorizationRequest.setApproved(true);
                    String clientAuthentication = UaaSecurityContextUtils.getClientAuthenticationMethod(clientAuth);
                    if (clientAuthentication != null) {
                        authorizationRequest.getExtensions().put(ClaimConstants.CLIENT_AUTH_METHOD, clientAuthentication);
                    }
                }

                OAuth2Request storedOAuth2Request = oAuth2RequestFactory.createOAuth2Request(authorizationRequest);

                SecurityContextHolder
                        .getContext()
                        .setAuthentication(new OAuth2Authentication(storedOAuth2Request, userAuthentication));

                onSuccessfulAuthentication();
            }
        } catch (AuthenticationException failed) {
            log.debug("Authentication request failed: {}", failed.getMessage());
            onUnsuccessfulAuthentication();
            authenticationEntryPoint.commence(request, response, failed);
            return;
        } catch (OAuth2Exception failed) {
            String message = failed.getMessage();
            log.debug("Authentication request failed with Oauth exception: {}", message);
            InsufficientAuthenticationException ex = new InsufficientAuthenticationException(message, failed);
            onUnsuccessfulAuthentication();
            authenticationEntryPoint.commence(request, response, ex);
            return;
        }

        chain.doFilter(request, response);
    }

    private Map<String, String> getSingleValueMap(HttpServletRequest request) {
        Map<String, String> map = new HashMap<>();
        Map<String, String[]> parameters = request.getParameterMap();
        for (Map.Entry<String, String[]> entry : parameters.entrySet()) {
            String[] values = entry.getValue();
            map.put(entry.getKey(), values != null && values.length > 0 ? values[0] : null);
        }
        return map;
    }

    protected void onSuccessfulAuthentication() {
        // do nothing
    }

    protected void onUnsuccessfulAuthentication() {
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
        String grantType = request.getParameter(GRANT_TYPE);
        log.debug("Processing token user authentication for grant:{}", UaaStringUtils.getCleanedUserControlString(grantType));
        Authentication authResult = null;
        if (GRANT_TYPE_PASSWORD.equals(grantType)) {
            Authentication credentials = extractCredentials(request);
            log.debug("Authentication credentials found password grant for '{}'", credentials.getName());
            authResult = authenticationManager.authenticate(credentials);

            if (authResult != null && authResult.isAuthenticated() && authResult instanceof UaaAuthentication uaaAuthentication
                    && SessionUtils.isPasswordChangeRequired(request.getSession())) {
                throw new PasswordChangeRequiredException(uaaAuthentication, "password change required");
            }


            return authResult;
        } else if (GRANT_TYPE_SAML2_BEARER.equals(grantType)) {
            log.debug("{} found. Attempting authentication with assertion", GRANT_TYPE_SAML2_BEARER);
            String assertion = request.getParameter("assertion");
            if (assertion != null && saml2BearerGrantAuthenticationConverter != null) {
                resolveRegistrationId(request);

                log.debug("Attempting SAML authentication for token endpoint.");
                try {
                    authResult = saml2BearerGrantAuthenticationConverter.convert(request);
                } catch (AuthenticationException e) {
                    String errorMessage = e instanceof Saml2AuthenticationException saml2AuthenticationException ?
                            saml2AuthenticationException.getSaml2Error().getDescription() : e.getMessage();
                    log.debug(errorMessage, e);
                    throw new InsufficientAuthenticationException(errorMessage);
                } catch (Exception e) {
                    String errorMessage = "Error setting assertion in SAML filter";
                    log.error(errorMessage, e);
                    throw new InsufficientAuthenticationException(errorMessage);
                }
            } else {
                log.debug("No assertion or filter, not attempting SAML authentication for token endpoint.");
                throw new InsufficientAuthenticationException("SAML Assertion is missing");
            }
        } else if (GRANT_TYPE_JWT_BEARER.equals(grantType)) {
            log.debug("{} found. Attempting authentication with assertion", GRANT_TYPE_JWT_BEARER);
            String assertion = request.getParameter("assertion");
            if (assertion != null && externalOAuthAuthenticationManager != null) {
                IdentityProvider<OIDCIdentityProviderDefinition> oidcProxy = externalOAuthAuthenticationManager.getOidcProxyIdpForTokenExchange(request);
                if (oidcProxy != null) {
                    log.debug("Forward OIDC JWT authentication to oidc proxy");
                    String idpAssertion = externalOAuthAuthenticationManager.oidcJwtBearerGrant(
                            (UaaAuthenticationDetails) authenticationDetailsSource.buildDetails(request),
                            oidcProxy, assertion);
                    assertion = idpAssertion != null ? idpAssertion : assertion;
                } else {
                    log.debug("Attempting OIDC JWT authentication for token endpoint.");
                }

                ExternalOAuthCodeToken token = new ExternalOAuthCodeToken(null, null, null, assertion, null, null);
                token.setRequestContextPath(getContextPath(request));
                authResult = externalOAuthAuthenticationManager.authenticate(token);
            } else {
                log.debug("No assertion or authentication manager, not attempting JWT bearer authentication for token endpoint.");
                throw new InsufficientAuthenticationException("Assertion is missing");
            }
        } else if (GRANT_TYPE_TOKEN_EXCHANGE.equals(grantType)) {
            TokenExchangeData token = getSubjectToken(request);
            if (token != null && this.tokenExchangeAuthenticationManager != null) {
                authResult = this.tokenExchangeAuthenticationManager.authenticate(token);
            } else {
                log.debug("No subject_token or authentication manager, not attempting JWT token-exchange for token endpoint.");
                throw new InsufficientAuthenticationException("Invalid or missing subject_token");
            }
        }

        if (authResult != null && authResult.isAuthenticated()) {
            log.debug("Authentication success: {}", authResult.getName());
            return authResult;
        }
        return null;
    }

    protected TokenExchangeData getSubjectToken(HttpServletRequest request) {
        String subjectToken = request.getParameter("subject_token");
        if (!hasText(subjectToken)) {
            return null;
        }
        String subjectTokenType = request.getParameter("subject_token_type");
        String idToken = null;
        String accessToken = null;
        if (TOKEN_TYPE_ACCESS.equals(subjectTokenType)) {
            accessToken = subjectToken;
        } else if (TOKEN_TYPE_ID.equals(subjectTokenType)) {
            idToken = subjectToken;
        }
        TokenExchangeData token = new TokenExchangeData(
                null,
                null,
                null,
                idToken,
                accessToken,
                null,
                new UaaAuthenticationDetails(request)
        );
        token.setRequestContextPath(getContextPath(request));
        return token;
    }

    private void resolveRegistrationId(HttpServletRequest request) {
        RequestMatcher.MatchResult result = this.requestMatcher.matcher(request);
        if (!result.isMatch()) {
            return;
        }
        String registrationId = result.getVariables().get("registrationId");
        if (registrationId == null) {
            return;
        }
        request.setAttribute("registrationId", registrationId);

    }

    private String getContextPath(HttpServletRequest request) {
        StringBuffer requestURL = request.getRequestURL();
        return requestURL.substring(0, requestURL.length() - request.getServletPath().length());
    }
}
