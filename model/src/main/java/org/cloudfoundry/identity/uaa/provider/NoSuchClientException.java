package org.cloudfoundry.identity.uaa.provider;

import org.springframework.security.oauth2.provider.ClientRegistrationException;

public class NoSuchClientException extends ClientRegistrationException {

	public NoSuchClientException(String msg) {
		super(msg);
	}

	public NoSuchClientException(String msg, Throwable cause) {
		super(msg, cause);
	}

}
