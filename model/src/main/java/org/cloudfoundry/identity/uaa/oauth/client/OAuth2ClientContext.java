package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public interface OAuth2ClientContext {

    /**
     * @return the current access token if any (may be null or empty)
     */
    OAuth2AccessToken getAccessToken();

    /**
     * @param accessToken the current access token
     */
    void setAccessToken(OAuth2AccessToken accessToken);

    /**
     * @return the current request if any (may be null or empty)
     */
    AccessTokenRequest getAccessTokenRequest();

    /**
     * Convenience method for saving state in the {@link OAuth2ClientContext}.
     * 
     * @param stateKey the key to use to save the state
     * @param preservedState the state to be saved
     */
    void setPreservedState(String stateKey, Object preservedState);

    /**
     * @param stateKey the state key to lookup
     * @return the state preserved with this key (if any)
     */
    Object removePreservedState(String stateKey);

}