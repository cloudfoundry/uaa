package org.cloudfoundry.identity.uaa.oauth.common.exceptions;

@SuppressWarnings("serial")
public class InvalidTokenSignatureException extends InvalidTokenException {

	public InvalidTokenSignatureException(String msg, Throwable t) {
		super(msg, t);
	}

	public InvalidTokenSignatureException(String msg) {
		super(msg);
	}

}
