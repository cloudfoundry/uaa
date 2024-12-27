package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserApprovalRequiredException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.springframework.security.access.AccessDeniedException;

/**
 * Moved class AccessTokenProvider implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public interface AccessTokenProvider {

    /**
     * Obtain a new access token for the specified protected resource.
     * 
     * @param details The protected resource for which this provider is to obtain an access token.
     * @param parameters The parameters of the request giving context for the token details if any.
     * @return The access token for the specified protected resource. The return value may NOT be null.
     * @throws UserRedirectRequiredException If the provider requires the current user to be redirected for
     * authorization.
     * @throws UserApprovalRequiredException If the provider is ready to issue a token but only if the user approves
     * @throws AccessDeniedException If the user denies access to the protected resource.
     */
    OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest parameters)
            throws UserRedirectRequiredException, UserApprovalRequiredException, AccessDeniedException;

    /**
     * Whether this provider supports the specified resource.
     * 
     * @param resource The resource.
     * @return Whether this provider supports the specified resource.
     */
    boolean supportsResource(OAuth2ProtectedResourceDetails resource);

    /**
     * @param resource the resource for which a token refresh is required
     * @param refreshToken the refresh token to send
     * @return an access token
     */
    OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource, OAuth2RefreshToken refreshToken,
            AccessTokenRequest request) throws UserRedirectRequiredException;

    /**
     * @param resource The resource to check
     * @return true if this provider can refresh an access token
     */
    boolean supportsRefresh(OAuth2ProtectedResourceDetails resource);
}
