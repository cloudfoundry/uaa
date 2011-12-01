package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.core.Authentication;

/**
 * Event which indicates an authentication failure due to an invalid username being supplied.
 *
 */
public class UserNotFoundEvent extends AbstractAuthenticationEvent {
	public UserNotFoundEvent(Authentication authentication) {
		super(authentication);
	}
}
