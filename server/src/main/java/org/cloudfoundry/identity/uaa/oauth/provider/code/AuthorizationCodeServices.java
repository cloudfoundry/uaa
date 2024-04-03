package org.cloudfoundry.identity.uaa.oauth.provider.code;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;

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
