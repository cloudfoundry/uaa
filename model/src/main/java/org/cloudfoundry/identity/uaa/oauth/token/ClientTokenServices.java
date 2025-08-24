package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.springframework.security.core.Authentication;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public interface ClientTokenServices {

    /**
     * Retrieve the access token for a given resource and user authentication (my be null).
     * 
     * @param resource the resource to be accessed
     * @param authentication the current user authentication (or null if there is none)
     * @return an access token if one has been stored, null otherwise
     */
    OAuth2AccessToken getAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication);

    /**
     * Save or update the access token for this resource and authentication (may be null).
     * 
     * @param resource the resource to be accessed
     * @param authentication the current user authentication (or null if there is none)
     * @param accessToken an access token to be stored
     */
    void saveAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication,
            OAuth2AccessToken accessToken);

    /**
     * Remove the token (if any) that is stored with the provided resource and authentication. If there is no such token
     * do nothing.
     * 
     * @param resource the resource to be accessed
     * @param authentication the current user authentication (or null if there is none)
     */
    void removeAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication);

}
