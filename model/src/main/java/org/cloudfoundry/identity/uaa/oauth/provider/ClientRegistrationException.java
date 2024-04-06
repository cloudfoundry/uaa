package org.cloudfoundry.identity.uaa.oauth.provider;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 framework
 */
public class ClientRegistrationException extends RuntimeException {
	
	public ClientRegistrationException(String msg) {
		super(msg);
	}

	public ClientRegistrationException(String msg, Throwable cause) {
		super(msg, cause);
	}

}
