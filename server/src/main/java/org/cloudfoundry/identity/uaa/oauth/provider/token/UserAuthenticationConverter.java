package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.springframework.security.core.Authentication;

import java.util.Map;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public interface UserAuthenticationConverter {

    final String AUTHORITIES = AccessTokenConverter.AUTHORITIES;

    final String USERNAME = "user_name";

    /**
     * Extract information about the user to be used in an access token (i.e. for resource servers).
     * 
     * @param userAuthentication an authentication representing a user
     * @return a map of key values representing the unique information about the user
     */
    Map<String, Object> convertUserAuthentication(Authentication userAuthentication);

    /**
     * Inverse of {@link #convertUserAuthentication(Authentication)}. Extracts an Authentication from a map.
     * 
     * @param map a map of user information
     * @return an Authentication representing the user or null if there is none
     */
    Authentication extractAuthentication(Map<String, ?> map);

}
