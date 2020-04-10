package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.user.UaaUser;

public class InvitedUserAuthenticatedEvent extends AuthEvent {
    public InvitedUserAuthenticatedEvent(UaaUser user) {
        super(user, true);
    }
}
