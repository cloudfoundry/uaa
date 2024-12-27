package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;

import java.io.Serial;
import java.io.Serializable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public class DefaultOAuth2ClientContext implements OAuth2ClientContext, Serializable {

    @Serial
    private static final long serialVersionUID = 7301862963115789109L;

    private transient OAuth2AccessToken accessToken;

    private transient AccessTokenRequest accessTokenRequest;

    private transient Map<String, Object> state = new ConcurrentHashMap<>();

    public DefaultOAuth2ClientContext() {
        this(new DefaultAccessTokenRequest());
    }

    public DefaultOAuth2ClientContext(AccessTokenRequest accessTokenRequest) {
        this.accessTokenRequest = accessTokenRequest;
    }

    public DefaultOAuth2ClientContext(OAuth2AccessToken accessToken) {
        this.accessToken = accessToken;
        this.accessTokenRequest = new DefaultAccessTokenRequest();
    }

    public OAuth2AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(OAuth2AccessToken accessToken) {
        this.accessToken = accessToken;
        this.accessTokenRequest.setExistingToken(accessToken);
    }

    public AccessTokenRequest getAccessTokenRequest() {
        return accessTokenRequest;
    }

    public void setPreservedState(String stateKey, Object preservedState) {
        state.clear();
        state.put(stateKey, preservedState);
    }

    public Object removePreservedState(String stateKey) {
        return state.remove(stateKey);
    }

}
