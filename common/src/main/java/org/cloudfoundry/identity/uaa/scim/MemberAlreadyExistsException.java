package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.scim.core.ScimException;
import org.springframework.http.HttpStatus;

public class MemberAlreadyExistsException extends ScimException {

	public MemberAlreadyExistsException(String message) {
		super(message, HttpStatus.CONFLICT);
	}
}
