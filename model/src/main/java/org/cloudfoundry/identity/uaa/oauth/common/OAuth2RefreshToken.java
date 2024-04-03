package org.cloudfoundry.identity.uaa.oauth.common;

import com.fasterxml.jackson.annotation.JsonValue;

public interface OAuth2RefreshToken {

	/**
	 * The value of the token.
	 * 
	 * @return The value of the token.
	 */
	@JsonValue
	String getValue();

}