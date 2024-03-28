package org.cloudfoundry.identity.uaa.oauth.exceptions;

public abstract class ClientAuthenticationException extends OAuth2Exception {

	public ClientAuthenticationException(String msg, Throwable t) {
		super(msg, t);
	}

	public ClientAuthenticationException(String msg) {
		super(msg);
	}

	@Override
	public int getHttpErrorCode() {
		return 400;
	}

	@Override
	public abstract String getOAuth2ErrorCode();
}
