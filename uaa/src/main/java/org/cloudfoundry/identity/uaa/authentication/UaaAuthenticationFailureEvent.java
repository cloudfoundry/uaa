package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * Event which indicates that a user authentication failed.
 *
 * This implies that the wrong credentials were supplied for a valid username.
 *
 * @author Luke Taylor
 */
public class UaaAuthenticationFailureEvent extends AbstractAuthenticationEvent {
	public UaaAuthenticationFailureEvent(Authentication authentication, UaaUser user) {
		super(authentication);
		Assert.notNull(user, "UaaUser object cannot be null");
	}
}
