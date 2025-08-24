package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.springframework.security.core.AuthenticationException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public interface ResourceServerTokenServices {

    /**
     * Load the credentials for the specified access token.
     *
     * @param accessToken The access token value.
     * @return The authentication for the access token.
     * @throws AuthenticationException If the access token is expired
     * @throws InvalidTokenException if the token isn't valid
     */
    OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException;

    /**
     * Retrieve the full access token details from just the value.
     * 
     * @param accessToken the token value
     * @return the full access token with client id etc.
     */
    OAuth2AccessToken readAccessToken(String accessToken);

}