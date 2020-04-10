
package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;

/**
 * Event which indicates that a user authentication failed.
 * 
 * This implies that the wrong credentials were supplied for a valid username.
 * 
 * @author Luke Taylor
 */
public class UserAuthenticationFailureEvent extends AbstractUaaAuthenticationEvent {
    private final UaaUser user;

    public UserAuthenticationFailureEvent(UaaUser user, Authentication authentication, String zoneId) {
        super(authentication, zoneId);
        this.user = user;
    }

    @Override
    public AuditEvent getAuditEvent() {
        return createAuditRecord(user.getId(), AuditEventType.UserAuthenticationFailure,
                        getOrigin(getAuthenticationDetails()), user.getUsername());
    }

    public UaaUser getUser() {
        return user;
    }
}
