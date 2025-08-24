package org.cloudfoundry.identity.uaa.oauth.token;

import lombok.Setter;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Calendar;
import java.util.Collections;
import java.util.List;

/**
 * Moved class AccessTokenProviderChain implementation of from spring-security-oauth2 into UAA
 * <p/>
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 * <p/>
 * Scope: OAuth2 client
 */
public class AccessTokenProviderChain extends OAuth2AccessTokenSupport
        implements AccessTokenProvider {

    private final List<AccessTokenProvider> chain;

    /**
     * Token services for long-term persistence of access tokens.
     */
    @Setter
    private ClientTokenServices clientTokenServices;

    // clockSkew is set via reflection in tests, so suppress local and static
    @SuppressWarnings({"FieldCanBeLocal", "java:S1170"})
    private final int clockSkew = 30; // NO SONAR

    public AccessTokenProviderChain(List<? extends AccessTokenProvider> chain) {
        this.chain = chain == null ? Collections.emptyList()
                : Collections.unmodifiableList(chain);
    }

    public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
        for (AccessTokenProvider tokenProvider : chain) {
            if (tokenProvider.supportsResource(resource)) {
                return true;
            }
        }
        return false;
    }

    public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
        for (AccessTokenProvider tokenProvider : chain) {
            if (tokenProvider.supportsRefresh(resource)) {
                return true;
            }
        }
        return false;
    }

    public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails resource,
                                               AccessTokenRequest request)
            throws UserRedirectRequiredException, AccessDeniedException {

        OAuth2AccessToken accessToken = null;
        OAuth2AccessToken existingToken;
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth instanceof AnonymousAuthenticationToken) {
            if (!resource.isClientOnly()) {
                throw new InsufficientAuthenticationException(
                        "Authentication is required to obtain an access token (anonymous not allowed)");
            }
        }

        if (resource.isClientOnly() || (auth != null && auth.isAuthenticated())) {
            existingToken = request.getExistingToken();
            if (existingToken == null && clientTokenServices != null) {
                existingToken = clientTokenServices.getAccessToken(resource, auth);
            }

            if (existingToken != null) {
                if (hasTokenExpired(existingToken)) {
                    if (clientTokenServices != null) {
                        clientTokenServices.removeAccessToken(resource, auth);
                    }
                    OAuth2RefreshToken refreshToken = existingToken.getRefreshToken();
                    if (refreshToken != null && !resource.isClientOnly()) {
                        accessToken = refreshAccessToken(resource, refreshToken, request);
                    }
                } else {
                    accessToken = existingToken;
                }
            }
        }
        // Give unauthenticated users a chance to get a token and be redirected

        if (accessToken == null) {
            // we need to obtain a new token.
            accessToken = obtainNewAccessTokenInternal(resource, request);

            if (accessToken == null) {
                throw new IllegalStateException(
                        "An OAuth 2 access token must be obtained or an exception thrown.");
            }
        }

        if (clientTokenServices != null
                && (resource.isClientOnly() || auth != null && auth.isAuthenticated())) {
            clientTokenServices.saveAccessToken(resource, auth, accessToken);
        }

        return accessToken;
    }

    protected OAuth2AccessToken obtainNewAccessTokenInternal(
            OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
            throws UserRedirectRequiredException, AccessDeniedException {

        if (request.isError()) {
            // there was an oauth error...
            throw OAuth2Exception.valueOf(request.toSingleValueMap());
        }

        for (AccessTokenProvider tokenProvider : chain) {
            if (tokenProvider.supportsResource(details)) {
                return tokenProvider.obtainAccessToken(details, request);
            }
        }

        throw new OAuth2AccessDeniedException(
                "Unable to obtain a new access token for resource '" + details.getId()
                        + "'. The provider manager is not configured to support it.",
                details);
    }

    /**
     * Obtain a new access token for the specified resource using the refresh token.
     *
     * @param resource     The resource.
     * @param refreshToken The refresh token.
     * @return The access token, or null if failed.
     */
    public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
                                                OAuth2RefreshToken refreshToken, AccessTokenRequest request)
            throws UserRedirectRequiredException {
        for (AccessTokenProvider tokenProvider : chain) {
            if (tokenProvider.supportsRefresh(resource)) {
                DefaultOAuth2AccessToken refreshedAccessToken = new DefaultOAuth2AccessToken(
                        tokenProvider.refreshAccessToken(resource, refreshToken,
                                request));
                if (refreshedAccessToken.getRefreshToken() == null) {
                    // Fixes gh-712
                    refreshedAccessToken.setRefreshToken(refreshToken);
                }
                return refreshedAccessToken;
            }
        }
        throw new OAuth2AccessDeniedException(
                "Unable to obtain a new access token for resource '" + resource.getId()
                        + "'. The provider manager is not configured to support it.",
                resource);
    }

    /**
     * Checks if the given {@link OAuth2AccessToken access token} should be considered to have expired based on the
     * token's expiration time and the clock skew.
     *
     * @param token the token to be checked
     * @return <code>true</code> if the token should be considered expired, <code>false</code> otherwise
     */
    private boolean hasTokenExpired(OAuth2AccessToken token) {
        Calendar now = Calendar.getInstance();
        Calendar expiresAt = (Calendar) now.clone();
        if (token.getExpiration() != null) {
            expiresAt.setTime(token.getExpiration());
            expiresAt.add(Calendar.SECOND, -clockSkew);
        }
        return now.after(expiresAt);
    }
}
