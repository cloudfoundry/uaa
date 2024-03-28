package org.cloudfoundry.identity.uaa.provider;

import org.springframework.security.oauth2.provider.ClientRegistrationException;

public class ClientAlreadyExistsException extends ClientRegistrationException {

	public ClientAlreadyExistsException(String msg) {
		super(msg);
	}

	public ClientAlreadyExistsException(String msg, Throwable cause) {
		super(msg, cause);
	}

}
