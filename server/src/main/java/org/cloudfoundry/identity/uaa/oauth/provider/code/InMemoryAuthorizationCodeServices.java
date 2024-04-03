package org.cloudfoundry.identity.uaa.oauth.provider.code;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;

import java.util.concurrent.ConcurrentHashMap;

public class InMemoryAuthorizationCodeServices extends RandomValueAuthorizationCodeServices {

	protected final ConcurrentHashMap<String, OAuth2Authentication> authorizationCodeStore = new ConcurrentHashMap<String, OAuth2Authentication>();

	@Override
	protected void store(String code, OAuth2Authentication authentication) {
		this.authorizationCodeStore.put(code, authentication);
	}

	@Override
	public OAuth2Authentication remove(String code) {
		OAuth2Authentication auth = this.authorizationCodeStore.remove(code);
		return auth;
	}

}
