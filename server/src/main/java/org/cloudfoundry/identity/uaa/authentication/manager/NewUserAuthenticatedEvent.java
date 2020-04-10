

package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.user.UaaUser;

/**
 * @author Dave Syer
 * 
 */
public class NewUserAuthenticatedEvent extends AuthEvent {

    public NewUserAuthenticatedEvent(UaaUser user) {
        super(user, true);
    }
}
