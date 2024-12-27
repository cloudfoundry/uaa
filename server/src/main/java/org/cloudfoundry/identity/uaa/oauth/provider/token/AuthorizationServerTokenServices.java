package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.springframework.security.core.AuthenticationException;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public interface AuthorizationServerTokenServices {

    /**
     * Create an access token associated with the specified credentials.
     * @param authentication The credentials associated with the access token.
     * @return The access token.
     * @throws AuthenticationException If the credentials are inadequate.
     */
    OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException;

    /**
     * Refresh an access token. The authorization request should be used for 2 things (at least): to validate that the
     * client id of the original access token is the same as the one requesting the refresh, and to narrow the scopes
     * (if provided).
     * 
     * @param refreshToken The details about the refresh token.
     * @param tokenRequest The incoming token request.
     * @return The (new) access token.
     * @throws AuthenticationException If the refresh token is invalid or expired.
     */
    OAuth2AccessToken refreshAccessToken(String refreshToken, TokenRequest tokenRequest)
            throws AuthenticationException;

    /**
     * Retrieve an access token stored against the provided authentication key, if it exists.
     * 
     * @param authentication the authentication key for the access token
     * 
     * @return the access token or null if there was none
     */
    OAuth2AccessToken getAccessToken(OAuth2Authentication authentication);

}