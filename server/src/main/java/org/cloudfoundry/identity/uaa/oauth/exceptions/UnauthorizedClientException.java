package org.cloudfoundry.identity.uaa.oauth.exceptions;

public class UnauthorizedClientException extends ClientAuthenticationException {

	public UnauthorizedClientException(String msg, Throwable t) {
		super(msg, t);
	}

	public UnauthorizedClientException(String msg) {
		super(msg);
	}

	@Override
	public int getHttpErrorCode() {
		// The spec says this can be unauthorized
		return 401;
	}

	@Override
	public String getOAuth2ErrorCode() {
		return "unauthorized_client";
	}
}
