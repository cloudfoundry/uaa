package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;

public interface AuthenticationKeyGenerator {

	/**
	 * @param authentication an OAuth2Authentication
	 * @return a unique key identifying the authentication
	 */
	String extractKey(OAuth2Authentication authentication);

}
