package org.cloudfoundry.identity.uaa.oauth.exceptions;

public class BadClientCredentialsException extends ClientAuthenticationException {

	public BadClientCredentialsException() {
		super("Bad client credentials");
	}

	@Override
	public int getHttpErrorCode() {
		return 401;
	}

	@Override
	public String getOAuth2ErrorCode() {
		return "invalid_client";
	}
}
