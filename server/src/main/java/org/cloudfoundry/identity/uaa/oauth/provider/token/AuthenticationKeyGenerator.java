package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;

/**
 * Moved class AuthenticationKeyGenerator implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public interface AuthenticationKeyGenerator {

    /**
     * @param authentication an OAuth2Authentication
     * @return a unique key identifying the authentication
     */
    String extractKey(OAuth2Authentication authentication);

}
