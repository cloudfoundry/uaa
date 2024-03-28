package org.cloudfoundry.identity.uaa.oauth.exceptions;

public class InvalidRequestException extends ClientAuthenticationException {

	public InvalidRequestException(String msg, Throwable t) {
		super(msg, t);
	}

	public InvalidRequestException(String msg) {
		super(msg);
	}

	@Override
	public String getOAuth2ErrorCode() {
		return "invalid_request";
	}
}
