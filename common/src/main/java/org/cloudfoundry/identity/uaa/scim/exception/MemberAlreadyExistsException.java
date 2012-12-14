package org.cloudfoundry.identity.uaa.scim.exception;

import org.springframework.http.HttpStatus;

public class MemberAlreadyExistsException extends ScimException {

	public MemberAlreadyExistsException(String message) {
		super(message, HttpStatus.CONFLICT);
	}
}
