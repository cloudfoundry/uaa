package org.cloudfoundry.identity.uaa.event;

import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * Event which indicates that a user authentication failed.
 *
 * This implies that the wrong credentials were supplied for a valid username.
 *
 * @author Luke Taylor
 */
public class UserAuthenticationFailureEvent extends AbstractUaaAuthenticationEvent {
	private final UaaUser user;

	public UserAuthenticationFailureEvent(UaaUser user, Authentication authentication) {
		super(authentication);
		Assert.notNull(user, "UaaUser object cannot be null");
		this.user = user;
	}

	@Override
	void process(UaaAuditService auditor) {
		auditor.userAuthenticationFailure(user);
	}
}
