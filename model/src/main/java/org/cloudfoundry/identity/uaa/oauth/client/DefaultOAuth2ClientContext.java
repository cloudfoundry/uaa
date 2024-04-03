package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;

import java.io.Serializable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DefaultOAuth2ClientContext implements OAuth2ClientContext, Serializable {

	private static final long serialVersionUID = 914967629530462926L;

	private OAuth2AccessToken accessToken;

	private AccessTokenRequest accessTokenRequest;

	private Map<String, Object> state = new ConcurrentHashMap<String, Object>();

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
