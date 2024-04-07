package org.cloudfoundry.identity.uaa.oauth.provider.client;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.AuthenticationException;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
@SuppressWarnings("serial")
public class OAuth2AuthenticationFailureEvent extends AbstractAuthenticationFailureEvent {

	public OAuth2AuthenticationFailureEvent(AuthenticationException exception) {
		super(new FailedOAuthClientAuthentication(), exception);
	}

}

@SuppressWarnings("serial")
class FailedOAuthClientAuthentication extends AbstractAuthenticationToken {

	public FailedOAuthClientAuthentication() {
		super(null);
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	@Override
	public Object getPrincipal() {
		return "UNKNOWN";
	}
	
}