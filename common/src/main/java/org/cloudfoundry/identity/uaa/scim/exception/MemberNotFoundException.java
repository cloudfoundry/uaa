package org.cloudfoundry.identity.uaa.scim.exception;

import org.springframework.http.HttpStatus;

public class MemberNotFoundException extends ScimException {

	public MemberNotFoundException(String message) {
		super(message, HttpStatus.NOT_FOUND);
	}
}
