package org.cloudfoundry.identity.uaa.oauth.exceptions;

public class InvalidClientException extends ClientAuthenticationException {

	public InvalidClientException(String msg) {
		super(msg);
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
