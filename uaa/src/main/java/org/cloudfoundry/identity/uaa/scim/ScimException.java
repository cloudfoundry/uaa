package org.cloudfoundry.identity.uaa.scim;

import org.springframework.http.HttpStatus;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class ScimException extends RuntimeException {

	private final HttpStatus status;

	public ScimException(String message, Throwable cause, HttpStatus status) {
		super(message, cause);
		this.status = status;
	}

	public ScimException(String message, HttpStatus status) {
		super(message);
		this.status = status;
	}

	public HttpStatus getStatus() {
		return status;
	}
}
