package org.cloudfoundry.identity.uaa.oauth.provider.code;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;

/**
 * Moved class AuthorizationCodeServices implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public interface AuthorizationCodeServices {

    /**
     * Create a authorization code for the specified authentications.
     * 
     * @param authentication The authentications to store.
     * @return The generated code.
     */
    String createAuthorizationCode(OAuth2Authentication authentication);

    /**
     * Consume a authorization code.
     * 
     * @param code The authorization code to consume.
     * @return The authentications associated with the code.
     * @throws InvalidGrantException If the authorization code is invalid or expired.
     */
    OAuth2Authentication consumeAuthorizationCode(String code)
            throws InvalidGrantException;

}
