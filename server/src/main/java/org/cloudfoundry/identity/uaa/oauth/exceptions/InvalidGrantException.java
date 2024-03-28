package org.cloudfoundry.identity.uaa.oauth.exceptions;

public class InvalidGrantException extends ClientAuthenticationException {

	public InvalidGrantException(String msg, Throwable t) {
		super(msg, t);
	}

	public InvalidGrantException(String msg) {
		super(msg);
	}

	@Override
	public String getOAuth2ErrorCode() {
		return "invalid_grant";
	}
}