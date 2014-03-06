package org.cloudfoundry.identity.uaa.codestore;

import org.springframework.http.HttpStatus;

public class CodeStoreException extends RuntimeException {

	private final HttpStatus status;

	public CodeStoreException(String message, Throwable cause, HttpStatus status) {
		super(message, cause);
		this.status = status;
	}

	public CodeStoreException(String message, HttpStatus status) {
		super(message);
		this.status = status;
	}

	public HttpStatus getStatus() {
		return status;
	}
}
