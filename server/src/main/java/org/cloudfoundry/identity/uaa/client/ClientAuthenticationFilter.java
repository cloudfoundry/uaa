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

package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.oauth.client.http.AccessTokenRequiredException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;

/**
 * An authentication filter for remote identity providers. Intended to be used
 * with Spring OAuth (1 or 2), since it is
 * aware of the redirect protocols employed by those frameworks. If used in the
 * PRE_AUTH_FILTER position of a regular
 * Spring Security filter chain the user will be redirected to the remote
 * provider to approve the access and return with
 * a valid access token. There are 2 main strategies to provide:
 *
 * <ul>
 * <li>
 * {@link #setPreAuthenticatedPrincipalSource(PreAuthenticatedPrincipalSource)
 * PreAuthenticatedPrincipalSource} (mandatory) provides a {@link Principal}
 * that can be authenticated by the authentication manager. An example would be
 * to contact the user info endpoint in a remote social provider and populate an
 * {@link Authentication} token with the user's profile data. The principal is
 * wrapped by</li>
 * <li>{@link #setAuthenticationManager(AuthenticationManager) Authentication
 * manager} is optional and defaults to a value that tries very hard to
 * authenticate everything it sees, on the assumption that it was obtained from
 * a trusted ID provider.</li>
 * </ul>
 *
 * To ensure that the default authentication manager successfully authenticates
 * the user, the principal source should
 * create a principal that itself is an {@link Authentication} and is already
 * authenticated. If you are not using the
 * default authentication manager then you are free to authenticate any way you
 * like (hence there is collaboration
 * between the principal source and authentication manager, and the principal
 * source can create an object of any type
 * that is understood by the authentication manager).
 *
 * @author Dave Syer
 *
 */
public class ClientAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

    private PreAuthenticatedPrincipalSource<?> principalSource;

    private boolean oauth2Available;

    /**
     * @param principalSource the PreAuthenticatedPrincipalSource to set
     */
    public void setPreAuthenticatedPrincipalSource(PreAuthenticatedPrincipalSource<?> principalSource) {
        this.principalSource = principalSource;
    }

    @Override
    public void afterPropertiesSet() {
        Assert.state(principalSource != null, "User info source must be provided");
        super.afterPropertiesSet();
        try {
            oauth2Available = ClassUtils.isPresent(AccessTokenRequiredException.class.getName(),
                    ClassUtils.getDefaultClassLoader());
        } catch (NoClassDefFoundError e) {
            // ignore
        }
    }

    public ClientAuthenticationFilter(String defaultFilterProcessesUrl) {
        setAuthenticationManager(new DefaultFriendlyAuthenticationManager());
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
        // Need to force a redirect via the OAuth client filter, so rethrow here
        // if OAuth related
        if (oauth2Available && failed instanceof SocialRedirectException exception) {
            throw exception.getUserRedirectException();
        }
        // If the exception is not a Spring Security exception this will
        // result in a default error page
        super.unsuccessfulAuthentication(request, response, failed);
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        try {
            return principalSource.getPrincipal();
        } catch (UserRedirectRequiredException e) {
            throw new SocialRedirectException(e);
        }
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return "N/A";
    }

    private static class DefaultFriendlyAuthenticationManager implements AuthenticationManager {

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {

            boolean authenticated = authentication.isAuthenticated();

            // If not already authenticated (the default) from the parent class
            if (authentication instanceof PreAuthenticatedAuthenticationToken preAuth && !authenticated) {
                // Look inside the principal and see if that was marked as
                // authenticated
                if (preAuth.getPrincipal() instanceof Authentication) {
                    Authentication principal = (Authentication) preAuth.getPrincipal();
                    preAuth = new PreAuthenticatedAuthenticationToken(principal, preAuth.getCredentials(),
                            principal.getAuthorities());
                    authenticated = principal.isAuthenticated();
                }
                preAuth.setAuthenticated(authenticated);

                authentication = preAuth;

            }

            return authentication;

        }

    }

    private static class SocialRedirectException extends AuthenticationException {

        public SocialRedirectException(UserRedirectRequiredException e) {
            super("Social user details extraction failed", e);
        }

        public UserRedirectRequiredException getUserRedirectException() {
            return (UserRedirectRequiredException) getCause();
        }

    }

}
