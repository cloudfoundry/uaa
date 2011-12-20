package org.cloudfoundry.identity.uaa.event;

import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.springframework.security.core.Authentication;

/**
 * Event which indicates that someone tried to authenticate as a non-existent
 * user.
 *
 * @author Luke Taylor
 */
public class UserNotFoundEvent extends AbstractUaaAuthenticationEvent {

	public UserNotFoundEvent(Authentication authentication) {
		super(authentication);
	}

	@Override
	void process(UaaAuditService auditor) {
		auditor.userNotFound(getAuthentication().getName(), (UaaAuthenticationDetails) getAuthentication().getDetails());
	}
}
